// Package cve implements a validation middleware that checks a package version
// against OSV.dev — the Open Source Vulnerability database, which aggregates
// advisories for both the npm and PyPI ecosystems (one API, no key). On a
// confirmed match the middleware rejects the package (mode: deny, the default)
// or allows it with a log + Metadata annotation (mode: warn).
//
// It is registry-agnostic: ctx.Registry is mapped to the OSV ecosystem
// ("npm" | "pypi"). Registries with no OSV ecosystem (e.g. maven) are skipped.
//
// The OSV client, bounded TTL cache and query/deny-message helpers live in
// internal/middleware/cveosv and are shared with the retrieval-stage
// cve-check-retrieval middleware (same endpoint + cache logic). When built via
// the adapter's FactoryWithClient, the client and its cache are shared per
// adapter with the retrieval middleware, so an untrusted request that runs both
// stages queries OSV once per (ecosystem,name,version).
package cve

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// ErrSourceUnavailable marks a transient OSV source failure (endpoint down,
// network error, timeout) as opposed to a real vulnerability verdict. errors.Is
// on this sentinel lets downstream stages (e.g. the deny-list recorder) skip
// recording infrastructure failures.
var ErrSourceUnavailable = errors.New("cve source unavailable")

// Backward-compatible defaults kept for existing tests.
const (
	defaultTimeout  = cveosv.DefaultTimeout
	defaultCacheTTL = cveosv.DefaultCacheTTL
)

// Middleware is the OSV-backed CVE validation middleware.
type Middleware struct {
	endpoint string
	mode     string // deny (default) | warn
	onError  string // fail_open (default) | fail_closed
	client   *cveosv.Client
	cache    *cveosv.Cache
}

// Name returns the config type string.
func (*Middleware) Name() string { return "cve-check" }

// Validate queries OSV for ecosystem/name/version. A confirmed match is denied
// or warned per mode; an OSV API failure follows on_error.
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	eco, ok := cveosv.Ecosystem(ctx.Registry)
	if !ok {
		// Not a registry OSV covers (e.g. maven); nothing to check.
		return nil
	}

	vulns, err := m.client.Query(ctx.Ctx, eco, ctx.PkgName, ctx.Version)
	if err != nil {
		return m.applyError(ctx, err)
	}
	return m.apply(ctx, vulns)
}

// apply enforces the configured mode on a (possibly cached) query result.
func (m *Middleware) apply(ctx *pipeline.PipelineContext, vulns []cveosv.Vuln) error {
	if len(vulns) == 0 {
		return nil
	}
	ids := cveosv.VulnIDsForDisplay(vulns, m.client.MinSeverity())
	switch m.mode {
	case cveosv.ModeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check: package has known vulnerabilities (served in warn mode)",
				"package", ctx.PkgName, "version", ctx.Version, "vulns", strings.Join(ids, ","))
		}
		ctx.Metadata["cve"] = ids
		return nil
	default: // deny
		return fmt.Errorf("cve-check: %s", cveosv.BuildDenyMessage(ctx.PkgName, ctx.Version, vulns, m.client.MinSeverity()))
	}
}

// applyError handles an OSV query failure per on_error.
func (m *Middleware) applyError(ctx *pipeline.PipelineContext, err error) error {
	switch m.onError {
	case cveosv.OnErrorFailClosed:
		if ctx.Log != nil {
			ctx.Log.Error("cve-check: vulnerability source unavailable; rejecting (fail_closed)", "err", err)
		}
		return fmt.Errorf("cve-check: %w", errors.Join(ErrSourceUnavailable, err))
	default: // fail_open
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check: vulnerability source unavailable; serving (fail_open)", "err", err)
		}
		return nil
	}
}

type params = cveosv.Params

// Backward-compatible aliases so existing tests keep compiling against the
// shared cveosv types.
type (
	osvVuln          = cveosv.Vuln
	osvQueryRequest  = cveosv.QueryRequest
	osvQueryResponse = cveosv.QueryResponse
)

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

// FactoryWithClient builds the middleware from its raw params node against a
// pre-built shared cveosv.Client, so the client and its cache are shared per
// adapter with the retrieval-stage cve-check-retrieval middleware. Only
// mode/on_error are taken from the params; endpoint/httpClient/cache come from
// the shared client. Adapters register this under "cve-check".
func FactoryWithClient(shared *cveosv.Client) pipeline.ValidationFactory {
	return func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("cve-check: decode params: %w", err)
			}
		}
		return &Middleware{
			endpoint: shared.Endpoint(),
			mode:     cveosv.DefaultedMode(pr.Mode),
			onError:  cveosv.DefaultedOnError(pr.OnError),
			client:   shared,
			cache:    shared.Cache(),
		}, nil
	}
}

// New constructs a cve-check middleware with injectable client and clock for
// deterministic tests. A nil client uses the configured timeout; a nil now uses
// time.Now().UTC().
func New(pr params, client *http.Client, now func() time.Time) *Middleware {
	c := cveosv.NewClient(cveosv.Params(pr), client, now)
	return &Middleware{
		endpoint: c.Endpoint(),
		mode:     c.Mode(),
		onError:  c.OnError(),
		client:   c,
		cache:    c.Cache(),
	}
}
