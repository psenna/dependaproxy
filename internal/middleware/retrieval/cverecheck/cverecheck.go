// Package cverecheck implements a retrieval middleware that re-checks a package
// version against OSV.dev on every serve — both the trusted (cache) and
// untrusted (fresh fetch) paths, including cache hits. This closes the gap where
// a CVE is published after the package was first validated: the validation-stage
// cve-check only runs on the first untrusted fetch, so a package stored before an
// advisory appears would otherwise be served forever. cve-check-retrieval must be
// FIRST in the retrieval list (outermost) so it runs even when a downstream cache
// middleware serves the artifact.
//
// It shares the OSV client + bounded TTL cache with the validation cve-check
// middleware via internal/middleware/cveosv. When built via the adapter's
// FactoryWithClient, both middlewares use one client/cache per adapter, so an
// untrusted request that runs both stages queries OSV once per
// (ecosystem,name,version); the retrieval stage still re-queries on every
// serve (retroactive-advisory guarantee), it just benefits from the cache the
// validation stage populated.
//
// When built via FactoryWithClientAndCache with a non-nil cvecheckcache.Store
// and a positive cacheDuration, the middleware additionally persists OSV results
// as severity-band counts in Postgres (see internal/middleware/retrieval/
// cvecheckcache). A fresh DB hit (now().Sub(entry.RetrievedAt) < cacheDuration)
// is applied from counts without an OSV round-trip, so a proxy restart does not
// re-query OSV for every package on the next serve. DB read/write errors log and
// fail open (fall through to OSV / serve anyway). The in-memory bounded TTL
// cache is always consulted first and short-circuits the DB cache while warm.
//
// mode deny (default): a confirmed match denies the serve with
// pipeline.ErrRejected, which adapters map to 403. mode warn: the artifact is
// served and the vuln IDs annotated in ctx.Metadata["cve-retrieval"].
// on_error fail_open (default): an OSV outage serves the artifact; fail_closed
// returns an error that is NOT ErrRejected, so adapters map it to 502 (an
// outage, not a policy advisory).
package cverecheck

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cvecheckcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Middleware re-checks OSV after the downstream chain resolves the artifact.
type Middleware struct {
	client        *cveosv.Client
	mode          string
	onError       string
	cache         cvecheckcache.Store // nil = persistent cache disabled
	cacheDuration time.Duration       // freshness window; <= 0 disables the persistent cache
	now           func() time.Time
	next          pipeline.RetrievalMiddleware
}

// Name returns the config type string.
func (*Middleware) Name() string { return "cve-check-retrieval" }

// Fetch resolves via next, then re-checks OSV on a hit. A denied version aborts
// the chain with pipeline.ErrRejected; an OSV failure follows on_error.
func (m *Middleware) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	hit, err := m.next.Fetch(ctx)
	if err != nil {
		return hit, err
	}
	if !hit {
		return false, nil
	}
	eco, ok := cveosv.Ecosystem(ctx.Registry)
	if !ok {
		// Not a registry OSV covers (e.g. maven); nothing to check.
		return true, nil
	}
	key := cveosv.Key(eco, ctx.PkgName, ctx.Version)
	// In-memory bounded TTL cache first (shared with the validation cve-check):
	// a warm entry applies the ID-listing path unchanged and never touches the
	// persistent cache.
	if vulns, cached := m.client.Cache().Get(key); cached {
		if len(vulns) == 0 {
			return true, nil
		}
		return m.apply(ctx, vulns)
	}
	if m.cache != nil && m.cacheDuration > 0 {
		return m.fetchWithCache(ctx, eco)
	}
	// Persistent cache disabled: existing behavior.
	vulns, qerr := m.client.Query(ctx.Ctx, eco, ctx.PkgName, ctx.Version)
	if qerr != nil {
		return m.applyError(ctx, qerr)
	}
	if len(vulns) == 0 {
		return true, nil
	}
	return m.apply(ctx, vulns)
}

// fetchWithCache handles the persistent-cache path: a fresh DB hit applies from
// counts without an OSV round-trip; a stale/miss re-queries OSV, persists the
// counts, then applies (ID-listing). DB read/write errors log and fail open.
func (m *Middleware) fetchWithCache(ctx *pipeline.PipelineContext, eco string) (bool, error) {
	entry, gerr := m.cache.Get(ctx.Ctx, eco, ctx.PkgName, ctx.Version)
	if gerr != nil {
		// DB read error: log + fail open, fall through to OSV.
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check-retrieval: cache read failed; querying OSV", "err", gerr)
		}
	} else if entry != nil && m.now().Sub(entry.RetrievedAt) < m.cacheDuration {
		// Fresh DB hit: apply from counts without an OSV round-trip.
		return m.applyFromCounts(ctx, entry)
	}
	// Stale or miss: query OSV, persist the counts, then apply (ID-listing).
	vulns, qerr := m.client.Query(ctx.Ctx, eco, ctx.PkgName, ctx.Version)
	if qerr != nil {
		return m.applyError(ctx, qerr)
	}
	counts := toCacheCounts(cveosv.CountBySeverity(vulns))
	if perr := m.cache.Put(ctx.Ctx, eco, ctx.PkgName, ctx.Version, counts, m.now()); perr != nil {
		// DB write error: log + fail open, serve anyway.
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check-retrieval: cache write failed; serving", "err", perr)
		}
	}
	if len(vulns) == 0 {
		return true, nil
	}
	return m.apply(ctx, vulns)
}

// toCacheCounts converts cveosv.Counts (the shared severity-band tally) to the
// cvecheckcache.Counts the store persists.
func toCacheCounts(c cveosv.Counts) cvecheckcache.Counts {
	return cvecheckcache.Counts{Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, Unknown: c.Unknown}
}

// toOSVCounts converts a stored cvecheckcache.Counts back to cveosv.Counts so
// the shared FilterByMinSeverity/Total helpers apply.
func toOSVCounts(c cvecheckcache.Counts) cveosv.Counts {
	return cveosv.Counts{Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, Unknown: c.Unknown}
}

// applyFromCounts enforces the configured mode on a fresh persistent-cache hit,
// re-applying the current min_severity threshold to the stored counts.
func (m *Middleware) applyFromCounts(ctx *pipeline.PipelineContext, e *cvecheckcache.Entry) (bool, error) {
	c := toOSVCounts(e.Counts).FilterByMinSeverity(m.client.MinSeverity())
	if c.Total() == 0 {
		return true, nil
	}
	msg := cveosv.BuildDenyMessageFromCounts(ctx.PkgName, ctx.Version, c, m.client.MinSeverity())
	switch m.mode {
	case cveosv.ModeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check-retrieval: serving vulnerable package (warn mode, cached)", "package", ctx.PkgName, "version", ctx.Version, "counts", msg)
		}
		ctx.Metadata["cve-retrieval"] = []string{msg}
		return true, nil
	default: // deny
		return false, fmt.Errorf("%s: %w", msg, pipeline.ErrRejected)
	}
}

// apply enforces the configured mode on a confirmed OSV match.
func (m *Middleware) apply(ctx *pipeline.PipelineContext, vulns []cveosv.Vuln) (bool, error) {
	ids := cveosv.VulnIDsForDisplay(vulns, m.client.MinSeverity())
	switch m.mode {
	case cveosv.ModeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check-retrieval: serving vulnerable package (warn mode)", "package", ctx.PkgName, "version", ctx.Version, "vulns", strings.Join(ids, ","))
		}
		ctx.Metadata["cve-retrieval"] = ids
		return true, nil
	default: // deny
		return false, fmt.Errorf("%s: %w", cveosv.BuildDenyMessage(ctx.PkgName, ctx.Version, vulns, m.client.MinSeverity()), pipeline.ErrRejected)
	}
}

// applyError handles an OSV query failure per on_error.
func (m *Middleware) applyError(ctx *pipeline.PipelineContext, err error) (bool, error) {
	switch m.onError {
	case cveosv.OnErrorFailClosed:
		if ctx.Log != nil {
			ctx.Log.Error("cve-check-retrieval: OSV unavailable; denying (fail_closed)", "err", err)
		}
		// NOT ErrRejected → adapters map this to 502 (outage, not an advisory).
		return false, fmt.Errorf("cve-check-retrieval: %w", err)
	default: // fail_open
		if ctx.Log != nil {
			ctx.Log.Warn("cve-check-retrieval: OSV unavailable; serving (fail_open)", "err", err)
		}
		return true, nil
	}
}

// Evict pass-through so rp.Cache stays wired when this middleware is the Head.
func (m *Middleware) Evict(ctx *pipeline.PipelineContext) error {
	if e, ok := m.next.(pipeline.Evictor); ok {
		return e.Evict(ctx)
	}
	return nil
}

// New constructs a Middleware wrapping next with an injected clock (for tests).
// A nil now uses time.Now().UTC(); a nil client uses the configured timeout.
// The persistent cache is disabled (nil store, zero duration).
func New(pr cveosv.Params, client *http.Client, next pipeline.RetrievalMiddleware, now func() time.Time) *Middleware {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Middleware{client: cveosv.NewClient(pr, client, now), mode: pr.Mode, onError: pr.OnError, now: now, next: next}
}

// Factory builds the middleware from its raw params node, registered by each
// adapter under "cve-check-retrieval".
var Factory pipeline.RetrievalFactory = func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
	var pr cveosv.Params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("cve-check-retrieval: decode params: %w", err)
		}
	}
	return New(pr, nil, next, time.Now), nil
}

// FactoryWithClient builds the middleware from its raw params node against a
// pre-built shared cveosv.Client, so the client and its cache are shared per
// adapter with the validation-stage cve-check middleware. Only mode/on_error
// are taken from the params; endpoint/httpClient/cache come from the shared
// client. The persistent cache is disabled. Adapters register this under
// "cve-check-retrieval".
func FactoryWithClient(shared *cveosv.Client) pipeline.RetrievalFactory {
	return FactoryWithClientAndCache(shared, nil, 0, nil)
}

// FactoryWithClientAndCache is FactoryWithClient with an optional persistent
// cvecheckcache.Store: when cache is non-nil and cacheDuration is positive, the
// built middleware persists OSV results as severity-band counts and serves fresh
// DB hits from counts without an OSV round-trip. A nil now uses time.Now().UTC().
func FactoryWithClientAndCache(shared *cveosv.Client, cache cvecheckcache.Store, cacheDuration time.Duration, now func() time.Time) pipeline.RetrievalFactory {
	return func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
		var pr cveosv.Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("cve-check-retrieval: decode params: %w", err)
			}
		}
		if now == nil {
			now = func() time.Time { return time.Now().UTC() }
		}
		return &Middleware{
			client:        shared,
			mode:          cveosv.DefaultedMode(pr.Mode),
			onError:       cveosv.DefaultedOnError(pr.OnError),
			cache:         cache,
			cacheDuration: cacheDuration,
			now:           now,
			next:          next,
		}, nil
	}
}
