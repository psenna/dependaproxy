// Package cveosv contains the shared OSV.dev client and bounded TTL cache used
// by both the validation cve-check middleware and the retrieval
// cve-check-retrieval middleware. It imports only the standard library so both
// middleware packages (and any future one) can reuse it without creating an
// import cycle through the pipeline package.
package cveosv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults used when the corresponding param is omitted.
const (
	DefaultEndpoint = "https://api.osv.dev"
	DefaultMode     = ModeDeny
	DefaultOnError  = OnErrorFailOpen
	DefaultTimeout  = 10 * time.Second
	DefaultCacheTTL = time.Hour
	DefaultCacheMax = 4096
)

// Modes and error policies.
const (
	ModeDeny = "deny"
	ModeWarn = "warn"

	OnErrorFailOpen   = "fail_open"
	OnErrorFailClosed = "fail_closed"
)

// Severity bands used for min_severity filtering and ID[band] rendering.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityNone     = "none"
	SeverityUnknown  = "unknown"
)

// SeverityRank maps a severity band to an ordering so min_severity thresholds
// can be compared. Unknown/unrecognized bands rank 0 (below low).
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// DefaultedMinSeverity normalizes a min_severity param: lowercase + trim, and
// only critical/high/medium/low are accepted. Empty, "none", and unrecognized
// values all mean "no threshold" (return ""), so "none" is equivalent to unset.
func DefaultedMinSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return s
	default:
		return ""
	}
}

// DefaultedEndpoint returns e, or DefaultEndpoint when e is empty. It lets
// callers that share a pre-built Client apply the same per-field defaulting
// NewClient uses without re-deriving the whole client.
func DefaultedEndpoint(e string) string {
	if e == "" {
		return DefaultEndpoint
	}
	return e
}

// DefaultedMode returns m, or DefaultMode when m is empty.
func DefaultedMode(m string) string {
	if m == "" {
		return DefaultMode
	}
	return m
}

// DefaultedOnError returns o, or DefaultOnError when o is empty.
func DefaultedOnError(o string) string {
	if o == "" {
		return DefaultOnError
	}
	return o
}

// Vuln is one vulnerability record in an OSV query response. Only the fields
// surfaced in deny/warn messages are kept. Severity is the derived band
// (critical/high/medium/low/unknown) and is never serialized back to OSV.
type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity string   `json:"-"`
}

// osvSeverity is one entry in an OSV vuln's "severity" array (a CVSS vector).
type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvRawVuln is the full OSV vuln record as returned by /v1/query. Only the
// fields needed to derive a severity band are kept.
type osvRawVuln struct {
	ID               string        `json:"id"`
	Summary          string        `json:"summary"`
	Aliases          []string      `json:"aliases"`
	Severity         []osvSeverity `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// QueryRequest is the body POSTed to OSV /v1/query.
type QueryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

// QueryResponse is the OSV /v1/query response envelope.
type QueryResponse struct {
	Vulns []Vuln `json:"vulns"`
}

// Params is the shared yaml-decoded configuration for an OSV-backed middleware
// (endpoint/mode/on_error/timeout/cache_ttl/min_severity). Both cve-check and
// cve-check-retrieval decode their params into this type.
type Params struct {
	Endpoint    string        `yaml:"endpoint"`
	Mode        string        `yaml:"mode"`
	OnError     string        `yaml:"on_error"`
	Timeout     time.Duration `yaml:"timeout"`
	CacheTTL    time.Duration `yaml:"cache_ttl"`
	MinSeverity string        `yaml:"min_severity"`
}

// Ecosystem maps a pipeline registry name to an OSV ecosystem. Only registries
// OSV covers are recognized ("npm" | "pypi" | "goproxy"); anything else returns
// ok=false so callers skip the check. OSV's Go ecosystem is literally "Go".
func Ecosystem(registry string) (string, bool) {
	switch registry {
	case "npm", "pypi":
		return registry, true
	case "goproxy":
		return "Go", true
	default:
		return "", false
	}
}

// Key derives the cache key for one ecosystem/name/version triple.
func Key(eco, name, version string) string {
	return eco + "|" + name + "|" + version
}

// Cache is a tiny, concurrency-safe TTL cache for OSV query results. It is
// bounded by Max entries so a long-running proxy can't leak memory across
// thousands of distinct versions: once full it purges expired entries, and if
// still full it drops the new entry (the next request simply re-queries OSV).
type Cache struct {
	mu    sync.Mutex
	TTL   time.Duration
	Max   int
	now   func() time.Time
	items map[string]cacheEntry
}

type cacheEntry struct {
	vulns  []Vuln
	expiry time.Time
}

// NewCache returns an empty Cache. A nil now falls back to time.Now().UTC().
func NewCache(ttl time.Duration, max int, now func() time.Time) *Cache {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Cache{TTL: ttl, Max: max, now: now, items: map[string]cacheEntry{}}
}

// Get returns the cached query result for key, deleting it if expired.
func (c *Cache) Get(key string) ([]Vuln, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return nil, false
	}
	if c.now().After(e.expiry) {
		delete(c.items, key)
		return nil, false
	}
	return e.vulns, true
}

// Put stores a query result for key. If the cache is full it purges expired
// entries first; if still full it drops the new entry rather than grow
// unbounded.
func (c *Cache) Put(key string, vulns []Vuln) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.Max {
		c.purgeExpiredLocked()
	}
	if len(c.items) >= c.Max {
		return // full even after purging; skip rather than grow unbounded
	}
	c.items[key] = cacheEntry{vulns: vulns, expiry: c.now().Add(c.TTL)}
}

// purgeExpiredLocked deletes every expired entry. Callers hold c.mu.
func (c *Cache) purgeExpiredLocked() {
	now := c.now()
	for k, e := range c.items {
		if now.After(e.expiry) {
			delete(c.items, k)
		}
	}
}

// Client queries OSV.dev and caches results in a bounded TTL cache. It is safe
// for concurrent use.
type Client struct {
	endpoint    string
	mode        string
	onError     string
	minSeverity string
	httpClient  *http.Client
	cache       *Cache
}

// NewClient builds a Client with the same defaulting as the original cve.New:
// empty endpoint/mode/onError and non-positive timeout/cache_ttl fall back to
// the defaults. A nil client uses the configured timeout; a nil now uses
// time.Now().UTC().
func NewClient(pr Params, client *http.Client, now func() time.Time) *Client {
	endpoint := DefaultedEndpoint(pr.Endpoint)
	mode := DefaultedMode(pr.Mode)
	onError := DefaultedOnError(pr.OnError)
	timeout := pr.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ttl := pr.CacheTTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Client{
		endpoint:    endpoint,
		mode:        mode,
		onError:     onError,
		minSeverity: DefaultedMinSeverity(pr.MinSeverity),
		httpClient:  client,
		cache:       NewCache(ttl, DefaultCacheMax, now),
	}
}

// Query returns the OSV vulns for one package version, consulting the cache
// first and populating it on a cache miss. The result is never nil (an empty
// vulns slice means "clean").
func (c *Client) Query(ctx context.Context, ecosystem, name, version string) ([]Vuln, error) {
	key := Key(ecosystem, name, version)
	if vulns, hit := c.cache.Get(key); hit {
		return vulns, nil
	}
	vulns, err := c.queryHTTP(ctx, ecosystem, name, version)
	if err != nil {
		return nil, err
	}
	c.cache.Put(key, vulns)
	return vulns, nil
}

// queryHTTP calls the OSV /v1/query endpoint for one package version.
func (c *Client) queryHTTP(ctx context.Context, ecosystem, name, version string) ([]Vuln, error) {
	req := QueryRequest{Version: version}
	req.Package.Ecosystem = ecosystem
	req.Package.Name = name
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cve-check: marshal query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cve-check: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cve-check: query %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("cve-check: OSV returned %s", resp.Status)
	}

	var parsed struct {
		Vulns []osvRawVuln `json:"vulns"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve-check: decode OSV response: %w", err)
	}
	out := make([]Vuln, 0, len(parsed.Vulns))
	for _, raw := range parsed.Vulns {
		out = append(out, Vuln{
			ID:       raw.ID,
			Summary:  raw.Summary,
			Aliases:  raw.Aliases,
			Severity: computeSeverity(raw),
		})
	}
	out = filterBySeverity(out, c.minSeverity)
	if out == nil {
		out = []Vuln{}
	}
	return out, nil
}

// Endpoint returns the configured (defaulted) OSV endpoint.
func (c *Client) Endpoint() string { return c.endpoint }

// Mode returns the configured (defaulted) mode.
func (c *Client) Mode() string { return c.mode }

// OnError returns the configured (defaulted) on_error policy.
func (c *Client) OnError() string { return c.onError }

// MinSeverity returns the normalized min_severity threshold ("" = no filter).
func (c *Client) MinSeverity() string { return c.minSeverity }

// HTTPClient returns the HTTP client used for OSV queries.
func (c *Client) HTTPClient() *http.Client { return c.httpClient }

// Cache returns the underlying bounded TTL cache (exposed for tests).
func (c *Client) Cache() *Cache { return c.cache }

// VulnIDs returns the ID of every vuln, preserving order.
func VulnIDs(vulns []Vuln) []string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	return ids
}

// VulnIDsWithSeverity returns the ID of every vuln, preserving order, with the
// severity band appended as "ID[band]" for known bands. Unknown/empty bands
// render as the bare ID.
func VulnIDsWithSeverity(vulns []Vuln) []string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		if v.Severity != "" && v.Severity != SeverityUnknown {
			ids = append(ids, v.ID+"["+v.Severity+"]")
		} else {
			ids = append(ids, v.ID)
		}
	}
	return ids
}

// BuildDenyMessage formats the deny-mode error text:
// "<name>@<version> has known vulnerabilities: <ids>", plus the first vuln's
// summary in parentheses when present. IDs render as "ID[band]" when the vuln
// has a known severity band. The caller prefixes its own middleware name (e.g.
// "cve-check: " or "cve-check-retrieval: ").
func BuildDenyMessage(name, version string, vulns []Vuln) string {
	msg := fmt.Sprintf("%s@%s has known vulnerabilities: %s", name, version, strings.Join(VulnIDsWithSeverity(vulns), ","))
	if len(vulns) > 0 && vulns[0].Summary != "" {
		msg += " (" + vulns[0].Summary + ")"
	}
	return msg
}

// filterBySeverity drops vulns below the min_severity threshold. An empty
// threshold (or "none", which normalizes to "") keeps everything.
func filterBySeverity(vulns []Vuln, minSeverity string) []Vuln {
	if minSeverity == "" {
		return vulns
	}
	threshold := SeverityRank(minSeverity)
	if threshold <= 0 {
		return vulns
	}
	kept := make([]Vuln, 0, len(vulns))
	for _, v := range vulns {
		if SeverityRank(v.Severity) >= threshold {
			kept = append(kept, v)
		}
	}
	return kept
}

// computeSeverity derives a severity band for one raw OSV vuln: the highest
// CVSS_V3/CVSS_V4 base score wins; otherwise the database_specific.severity
// (case-insensitive, MODERATE → medium); otherwise unknown.
func computeSeverity(raw osvRawVuln) string {
	best := -1.0
	for _, sev := range raw.Severity {
		if sev.Type != "CVSS_V3" && sev.Type != "CVSS_V4" {
			continue
		}
		if score, ok := parseCVSSBaseScore(sev.Score); ok && score > best {
			best = score
		}
	}
	if best >= 0 {
		return bandFromScore(best)
	}
	s := strings.ToLower(strings.TrimSpace(raw.DatabaseSpecific.Severity))
	if s == "moderate" {
		return SeverityMedium
	}
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return s
	default:
		return SeverityUnknown
	}
}

// bandFromScore maps a CVSS base score to a severity band.
func bandFromScore(score float64) string {
	switch {
	case score >= 9:
		return SeverityCritical
	case score >= 7:
		return SeverityHigh
	case score >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// parseCVSSBaseScore parses a CVSS vector and returns its base score. It
// supports CVSS v3.1 vectors (AV/AC/PR/UI/S/C/I/A) and CVSS v4 vectors
// (AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA). A v4 vector's explicit BS component wins
// when present; otherwise the v3.1 equation is applied with the v4 VC/VI/VA
// metrics mapped onto C/I/A. ok is false for malformed vectors.
func parseCVSSBaseScore(vector string) (float64, bool) {
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return 0, false
		}
		metrics[strings.ToUpper(strings.TrimSpace(kv[0]))] = strings.ToUpper(strings.TrimSpace(kv[1]))
	}
	if len(metrics) == 0 {
		return 0, false
	}
	if bs, ok := metrics["BS"]; ok {
		score, err := strconv.ParseFloat(bs, 64)
		if err != nil {
			return 0, false
		}
		return clampScore(score), true
	}

	av, ok := metricValue(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := metricValue(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	ui, ok := metricValue(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	scope := metrics["S"]
	if scope == "" {
		scope = "U" // v4 has no scope component
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := metricValue(metrics, "PR", prTable)
	if !ok {
		return 0, false
	}

	conf, integ, avail := 0.0, 0.0, 0.0
	if _, hasVC := metrics["VC"]; hasVC {
		conf, ok = metricValue(metrics, "VC", ciaTable)
		if !ok {
			return 0, false
		}
		integ, ok = metricValue(metrics, "VI", ciaTable)
		if !ok {
			return 0, false
		}
		avail, ok = metricValue(metrics, "VA", ciaTable)
		if !ok {
			return 0, false
		}
	} else {
		conf, ok = metricValue(metrics, "C", ciaTable)
		if !ok {
			return 0, false
		}
		integ, ok = metricValue(metrics, "I", ciaTable)
		if !ok {
			return 0, false
		}
		avail, ok = metricValue(metrics, "A", ciaTable)
		if !ok {
			return 0, false
		}
	}

	iss := 1 - (1-conf)*(1-integ)*(1-avail)
	var impact float64
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "C" {
		base = roundup(1.08 * (impact + exploitability))
	} else {
		base = roundup(impact + exploitability)
	}
	return clampScore(base), true
}

// ciaTable maps the C/I/A (and v4 VC/VI/VA) metric values to their CVSS v3.1
// impact weights.
var ciaTable = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

// metricValue looks up key in metrics and maps its value through table.
func metricValue(metrics map[string]string, key string, table map[string]float64) (float64, bool) {
	v, ok := metrics[key]
	if !ok {
		return 0, false
	}
	score, ok := table[v]
	return score, ok
}

// roundup implements the CVSS v3.1 Roundup function.
func roundup(x float64) float64 {
	intInput := math.Round(x * 100000)
	if math.Mod(intInput, 10000) == 0 {
		return intInput / 100000
	}
	return (math.Floor(intInput/10000) + 1) / 10
}

// clampScore bounds a base score to the CVSS [0,10] range.
func clampScore(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 10 {
		return 10
	}
	return score
}
