// Package cve implements a validation middleware that checks a package version
// against OSV.dev — the Open Source Vulnerability database, which aggregates
// advisories for both the npm and PyPI ecosystems (one API, no key). On a
// confirmed match the middleware rejects the package (mode: deny, the default)
// or allows it with a log + Metadata annotation (mode: warn).
//
// It is registry-agnostic: ctx.Registry is mapped to the OSV ecosystem
// ("npm" | "pypi"). Registries with no OSV ecosystem (e.g. maven) are skipped.
package cve

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

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Defaults used when the corresponding param is omitted.
const (
	defaultEndpoint = "https://api.osv.dev"
	defaultMode     = modeDeny
	defaultOnError  = onErrorFailOpen
	defaultTimeout  = 10 * time.Second
	defaultCacheTTL = time.Hour
)

// Modes and error policies.
const (
	modeDeny = "deny"
	modeWarn = "warn"

	onErrorFailOpen   = "fail_open"
	onErrorFailClosed = "fail_closed"
)

// osvVuln is one vulnerability record in an OSV query response. Only the fields
// surfaced in deny/warn messages are kept.
type osvVuln struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Aliases []string `json:"aliases"`
}

type osvQueryRequest struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// Middleware is the OSV-backed CVE validation middleware.
type Middleware struct {
	endpoint string
	mode     string // deny (default) | warn
	onError  string // fail_open (default) | fail_closed
	client   *http.Client
	cache    *ttlCache
}

// Name returns the config type string.
func (*Middleware) Name() string { return "cve-check" }

// Validate queries OSV for ecosystem/name/version. A confirmed match is denied
// or warned per mode; an OSV API failure follows on_error.
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	eco, ok := osvEcosystem(ctx.Registry)
	if !ok {
		// Not a registry OSV covers (e.g. maven); nothing to check.
		return nil
	}

	key := eco + "|" + ctx.PkgName + "|" + ctx.Version
	if vulns, hit := m.cache.get(key); hit {
		return m.apply(ctx, key, vulns)
	}

	vulns, err := m.query(ctx.Ctx, eco, ctx.PkgName, ctx.Version)
	if err != nil {
		return m.applyError(ctx, err)
	}
	m.cache.put(key, vulns)
	return m.apply(ctx, key, vulns)
}

// query calls the OSV /v1/query endpoint for one package version.
func (m *Middleware) query(ctx context.Context, ecosystem, name, version string) ([]osvVuln, error) {
	req := osvQueryRequest{Version: version}
	req.Package.Ecosystem = ecosystem
	req.Package.Name = name
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cve-check: marshal query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cve-check: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cve-check: query %s@%s: %w", name, version, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("cve-check: OSV returned %s", resp.Status)
	}

	var parsed osvQueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("cve-check: decode OSV response: %w", err)
	}
	if parsed.Vulns == nil {
		return []osvVuln{}, nil
	}
	return parsed.Vulns, nil
}

// apply enforces the configured mode on a (possibly cached) query result.
func (m *Middleware) apply(ctx *pipeline.PipelineContext, key string, vulns []osvVuln) error {
	if len(vulns) == 0 {
		return nil
	}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	summary := vulns[0].Summary
	switch m.mode {
	case modeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check: package has known vulnerabilities (served in warn mode)",
				"package", ctx.PkgName, "version", ctx.Version, "vulns", strings.Join(ids, ","))
		}
		ctx.Metadata["cve"] = ids
		return nil
	default: // deny
		msg := fmt.Sprintf("cve-check: %s@%s has known vulnerabilities: %s", ctx.PkgName, ctx.Version, strings.Join(ids, ","))
		if summary != "" {
			msg += " (" + summary + ")"
		}
		return fmt.Errorf("%s", msg)
	}
}

// applyError handles an OSV query failure per on_error.
func (m *Middleware) applyError(ctx *pipeline.PipelineContext, err error) error {
	switch m.onError {
	case onErrorFailClosed:
		if ctx.Log != nil {
			ctx.Log.Error("cve-check: vulnerability source unavailable; rejecting (fail_closed)", "err", err)
		}
		return fmt.Errorf("cve-check: %w", err)
	default: // fail_open
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check: vulnerability source unavailable; serving (fail_open)", "err", err)
		}
		return nil
	}
}

// osvEcosystem maps a pipeline registry name to an OSV ecosystem.
func osvEcosystem(registry string) (string, bool) {
	switch registry {
	case "npm", "pypi":
		return registry, true
	default:
		return "", false
	}
}

// ttlCache is a tiny, concurrency-safe TTL cache for OSV query results.
type ttlCache struct {
	mu    sync.Mutex
	ttl   time.Duration
	now   func() time.Time
	items map[string]ttlEntry
}

type ttlEntry struct {
	vulns  []osvVuln
	expiry time.Time
}

func newTTLCache(ttl time.Duration, now func() time.Time) *ttlCache {
	return &ttlCache{ttl: ttl, now: now, items: map[string]ttlEntry{}}
}

func (c *ttlCache) get(key string) ([]osvVuln, bool) {
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

func (c *ttlCache) put(key string, vulns []osvVuln) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = ttlEntry{vulns: vulns, expiry: c.now().Add(c.ttl)}
}

type params struct {
	Endpoint string        `yaml:"endpoint"`
	Mode     string        `yaml:"mode"`
	OnError  string        `yaml:"on_error"`
	Timeout  time.Duration `yaml:"timeout"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// Factory builds the middleware from its raw params node, registered by each
// adapter under "cve-check".
var Factory pipeline.ValidationFactory = func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("cve-check: decode params: %w", err)
		}
	}
	return New(pr, nil, nil), nil
}

// New constructs a cve-check middleware with injectable client and clock for
// deterministic tests. A nil client uses the configured timeout; a nil now uses
// time.Now().UTC().
func New(pr params, client *http.Client, now func() time.Time) *Middleware {
	endpoint := pr.Endpoint
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	mode := pr.Mode
	if mode == "" {
		mode = defaultMode
	}
	onError := pr.OnError
	if onError == "" {
		onError = defaultOnError
	}
	timeout := pr.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ttl := pr.CacheTTL
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &Middleware{
		endpoint: endpoint,
		mode:     mode,
		onError:  onError,
		client:   client,
		cache:    newTTLCache(ttl, now),
	}
}
