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
	"net/http"
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
// surfaced in deny/warn messages are kept.
type Vuln struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
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
// (endpoint/mode/on_error/timeout/cache_ttl). Both cve-check and
// cve-check-retrieval decode their params into this type.
type Params struct {
	Endpoint string        `yaml:"endpoint"`
	Mode     string        `yaml:"mode"`
	OnError  string        `yaml:"on_error"`
	Timeout  time.Duration `yaml:"timeout"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
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
	endpoint   string
	mode       string
	onError    string
	httpClient *http.Client
	cache      *Cache
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
		endpoint:   endpoint,
		mode:       mode,
		onError:    onError,
		httpClient: client,
		cache:      NewCache(ttl, DefaultCacheMax, now),
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

	var parsed QueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve-check: decode OSV response: %w", err)
	}
	if parsed.Vulns == nil {
		return []Vuln{}, nil
	}
	return parsed.Vulns, nil
}

// Endpoint returns the configured (defaulted) OSV endpoint.
func (c *Client) Endpoint() string { return c.endpoint }

// Mode returns the configured (defaulted) mode.
func (c *Client) Mode() string { return c.mode }

// OnError returns the configured (defaulted) on_error policy.
func (c *Client) OnError() string { return c.onError }

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

// BuildDenyMessage formats the deny-mode error text:
// "<name>@<version> has known vulnerabilities: <ids>", plus the first vuln's
// summary in parentheses when present. The caller prefixes its own middleware
// name (e.g. "cve-check: " or "cve-check-retrieval: ").
func BuildDenyMessage(name, version string, vulns []Vuln) string {
	msg := fmt.Sprintf("%s@%s has known vulnerabilities: %s", name, version, strings.Join(VulnIDs(vulns), ","))
	if len(vulns) > 0 && vulns[0].Summary != "" {
		msg += " (" + vulns[0].Summary + ")"
	}
	return msg
}
