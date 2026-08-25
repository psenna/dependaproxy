// Package adapter defines the registry-adapter plugin contract. Each registry
// (npm, pypi, maven, ...) is an Adapter built by a Factory from its
// RegistryConfig + shared Deps. The server builds all configured adapters and
// mounts each at its prefix. Adding a registry = one new package under
// internal/registry/<x> + one adapter.Register call; the shared core never
// changes.
package adapter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// Deps are shared dependencies passed to every adapter factory.
type Deps struct {
	DB                *sql.DB // shared postgres connection pool
	ProjectStore      project.Store
	DependencyTracker project.DependencyTracker // nil on the dispatch-only/default path
	Logger            *slog.Logger
	Now               func() time.Time
}

// Adapter is one registry plugin. It owns its data model, client, routes,
// per-registry middleware, and storage schema.
type Adapter interface {
	// Prefix is the URL path prefix this adapter is mounted at (e.g. "/npm").
	Prefix() string
	// Handler serves this registry's routes. The server strips the prefix
	// before dispatching, so the handler sees paths relative to its prefix.
	Handler() http.Handler
	// InvalidateProjectCache drops the cached Resolved pipelines for the given
	// project key in this adapter's project.Resolver, so the next request re-reads
	// the project store. Adapters without a resolver implement this as a no-op.
	InvalidateProjectCache(key string)
}

// Factory builds an adapter from its RegistryConfig + shared Deps. ctx is the
// server startup context; factories use it for any startup work (opening
// storage, initializing stores) so cancellation/timeouts propagate.
type Factory func(ctx context.Context, cfg config.RegistryConfig, deps Deps) (Adapter, error)

var factories = map[string]Factory{}

// Register registers an adapter factory by registry type. Called from each
// adapter package (via cmd/main import side-effects or explicit init).
func Register(typeName string, f Factory) {
	factories[typeName] = f
}

// CVESharedParams scans cfg for the first cve-check (validation) or
// cve-check-retrieval (retrieval) middleware params and returns them for
// building a shared cveosv.Client. Validation wins for the shared client
// fields (endpoint/mode/on_error/timeout/cache_ttl/min_severity); mode/on_error
// are left for the per-middleware factories to apply. CacheEnabled and
// CacheDuration are ALWAYS sourced from the retrieval cve-check-retrieval block
// (merged over the validation winner), so the persistent cve-check-retrieval
// cache can be enabled independently of which block wins the shared client
// fields. Returns zero Params (all defaults) if neither is configured.
func CVESharedParams(cfg config.RegistryConfig) cveosv.Params {
	var pr cveosv.Params
	found := false
	for _, m := range cfg.Validation {
		if m.Type == "cve-check" {
			pr = decodeCVEParams(m.Params)
			found = true
			break
		}
	}
	for _, m := range cfg.Retrieval {
		if m.Type == "cve-check-retrieval" {
			rp := decodeCVEParams(m.Params)
			if !found {
				pr = rp
			}
			pr.CacheEnabled = rp.CacheEnabled
			pr.CacheDuration = rp.CacheDuration
			break
		}
	}
	return pr
}

// decodeCVEParams decodes a middleware params node into cveosv.Params. A zero
// node or a decode error falls back to zero Params (all defaults).
func decodeCVEParams(n yaml.Node) cveosv.Params {
	var pr cveosv.Params
	if n.IsZero() {
		return pr
	}
	if err := n.Decode(&pr); err != nil {
		return cveosv.Params{}
	}
	return pr
}

// FirstMiddlewareParams decodes the params of the first middleware of type
// mwType found in ms into out (a pointer), leaving out at its zero value if
// no entry matches or its params fail to decode.
//
// This exists so an adapter Factory can read the OPERATOR's own static
// configuration for a middleware type BEFORE registering that type's
// pipeline.Registry factory — the read value is then baked into a "fixed"
// factory (e.g. guarddog.Factory(guarddog.NewRunner(pr)), instead of
// guarddog.Factory(nil)) so a later per-project admin-API override of that
// middleware cannot influence the fields the fixed factory pinned. See the
// security-review H4 fix and CVESharedParams above, which predates this as a
// bespoke, cve-specific version of the same pattern.
func FirstMiddlewareParams(ms []config.Middleware, mwType string, out interface{}) {
	for _, m := range ms {
		if m.Type != mwType {
			continue
		}
		if !m.Params.IsZero() {
			_ = m.Params.Decode(out) // best-effort; a malformed operator config surfaces later when the real factory decodes it again
		}
		return
	}
}

// Build builds all adapters for the configured registries, rejecting unknown
// types. ctx is passed to each factory so startup work respects its deadline.
func Build(ctx context.Context, cfgs []config.RegistryConfig, deps Deps) ([]Adapter, error) {
	out := make([]Adapter, 0, len(cfgs))
	for i, rc := range cfgs {
		f, ok := factories[rc.Type]
		if !ok {
			return nil, fmt.Errorf("registries[%d]: unknown registry type %q", i, rc.Type)
		}
		a, err := f(ctx, rc, deps)
		if err != nil {
			return nil, fmt.Errorf("registries[%d] %s: %w", i, rc.Type, err)
		}
		out = append(out, a)
	}
	return out, nil
}
