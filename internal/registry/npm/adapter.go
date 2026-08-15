package npm

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/mutation/stripscripts"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cvecheckcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/guarddog"
	"github.com/psenna/dependaproxy/internal/middleware/validation/malware"
	"github.com/psenna/dependaproxy/internal/middleware/validation/provenance"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

func init() { adapter.Register("npm", Factory) }

// Factory builds the npm adapter from its RegistryConfig + shared Deps.
func Factory(ctx context.Context, cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	client, err := New(cfg.Upstream, cfg.AllowedUpstreamHosts, nil)
	if err != nil {
		return nil, err
	}
	storage, err := OpenStorage(ctx, deps.DB)
	if err != nil {
		return nil, err
	}
	denyStore, err := denylist.OpenStore(ctx, deps.DB)
	if err != nil {
		return nil, err
	}

	// One OSV client (and its cache) shared by the validation cve-check and the
	// retrieval cve-check-retrieval middlewares, so an untrusted request that
	// runs both stages queries OSV once per (ecosystem,name,version).
	pr := adapter.CVESharedParams(cfg)
	sharedCVE := cveosv.NewClient(pr, nil, deps.Now)

	// Optional persistent Postgres cache of cve-check-retrieval results
	// (severity-band counts), so a proxy restart does not re-query OSV for every
	// package on the next serve. Enabled via cache_enabled in the
	// cve-check-retrieval params; cache_duration defaults to 7 days.
	var cveStore cvecheckcache.Store
	if pr.CacheEnabled {
		cveStore, err = cvecheckcache.OpenStore(ctx, deps.DB)
		if err != nil {
			return nil, err
		}
	}
	cacheDuration := cveosv.DefaultedCacheDuration(pr.CacheDuration)

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("deny-list-check", denylist.Factory(denyStore))
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.FactoryWithClient(sharedCVE))
	reg.RegisterValidation("malware-scan", malware.Factory)
	reg.RegisterValidation("guarddog-scan", guarddog.Factory(nil))
	reg.RegisterValidation("provenance-verify", provenance.Factory(NewProvenanceSource(client)))
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.FactoryWithClientAndCache(sharedCVE, cveStore, cacheDuration, deps.Now))
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("s3-cache", s3cache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)
	reg.RegisterMutation("strip-install-scripts", stripscripts.Factory)

	validation, err := reg.BuildValidation(cfg.Validation)
	if err != nil {
		return nil, err
	}
	retrieval, err := reg.BuildRetrieval(cfg.Retrieval)
	if err != nil {
		return nil, err
	}
	mp, err := reg.BuildMutation(cfg.Mutation)
	if err != nil {
		return nil, err
	}
	if len(cfg.Mutation) == 0 {
		// v1/v2 ship a single no-op mutation so the PreFetch/PostFetch hook
		// path is exercised; real mutations slot in via config.
		mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}
	}
	dlv, err := reg.BuildValidation([]config.Middleware{{Type: "deny-list-check"}})
	if err != nil {
		return nil, err
	}
	allowlist := denylist.DefaultRecordedMiddlewares
	if cfg.DenyList != nil && len(cfg.DenyList.RecordMiddlewares) > 0 {
		allowlist = cfg.DenyList.RecordMiddlewares
	}
	var onFailure func(*pipeline.PipelineContext, error)
	if cfg.DenyList == nil || cfg.DenyList.Enabled == nil || *cfg.DenyList.Enabled {
		onFailure = denylist.Recorder(denyStore, deps.Now, allowlist...)
	}
	hooks := project.ValidationHooks{Prepend: dlv.Chain[0], OnFailure: onFailure}

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	resolver := project.NewResolver(cfg.Type, reg, deps.ProjectStore, global, hooks)
	return &npmAdapter{
		prefix:   cfg.Prefix,
		storage:  storage,
		client:   client,
		resolver: resolver,
		tracker:  deps.DependencyTracker,
		logger:   deps.Logger,
		now:      deps.Now,
	}, nil
}
