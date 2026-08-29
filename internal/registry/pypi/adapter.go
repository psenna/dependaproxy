package pypi

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
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

func init() { adapter.Register("pypi", Factory) }

// Factory builds the pypi adapter from its RegistryConfig + shared Deps.
func Factory(ctx context.Context, cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	// PyPI file URLs live on files.pythonhosted.org, not pypi.org — ship it as
	// a built-in default so strict base-host equality doesn't break PyPI out of
	// the box. Operators add CDN hosts for mirrors via allowed_upstream_hosts.
	client, err := New(cfg.Upstream, append([]string{"files.pythonhosted.org"}, cfg.AllowedUpstreamHosts...), nil)
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

	// H4: guarddog-scan (exec binary/sandbox), provenance-verify (TUF trust-root
	// cache dir), and local-disk-cache (filesystem write root) each carry a
	// field that must never vary per project -- the admin API lets a project
	// override params for any middleware type its pipeline uses, and the
	// factories above this comment silently rebuild a fresh Runner/Verifier/
	// cache root from whatever params they're called with. Read the OPERATOR's
	// own static config for these three types now, before registering their
	// factories, and pin the dangerous fields to that reading: a project can
	// still turn guarddog-scan's mode from deny to warn, but it can no longer
	// point Binary at an arbitrary executable, disable Sandbox, redirect
	// TrustRootDir, or redirect the disk cache's write root.
	var guarddogPr guarddog.Params
	adapter.FirstMiddlewareParams(cfg.Validation, "guarddog-scan", &guarddogPr)
	guarddogRunner := guarddog.NewRunner(guarddogPr)

	var provenancePr provenance.Params
	adapter.FirstMiddlewareParams(cfg.Validation, "provenance-verify", &provenancePr)
	provenanceVerifier := provenance.NewSigstoreVerifier(provenancePr)

	var diskCachePr struct {
		Path string `yaml:"path"`
	}
	adapter.FirstMiddlewareParams(cfg.Retrieval, "local-disk-cache", &diskCachePr)

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("deny-list-check", denylist.Factory(denyStore))
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.FactoryWithClient(sharedCVE))
	reg.RegisterValidation("malware-scan", malware.Factory)
	reg.RegisterValidation("guarddog-scan", guarddog.Factory(guarddogRunner))
	reg.RegisterValidation("provenance-verify", provenance.FactoryWithVerifier(NewProvenanceSource(client), provenanceVerifier))
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.FactoryWithClientAndCache(sharedCVE, cveStore, cacheDuration, deps.Now))
	reg.RegisterRetrieval("local-disk-cache", localcache.FactoryFixedPath(diskCachePr.Path))
	reg.RegisterRetrieval("s3-cache", s3cache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

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
	// upstream_alias defaults to true: the alias never widens what can be
	// requested (it names the same (name, version, filename) triple /files/
	// already names) and lockfile portability is broken without it.
	aliasEnabled := cfg.UpstreamAlias == nil || *cfg.UpstreamAlias
	return &pypiAdapter{
		prefix:        cfg.Prefix,
		storage:       storage,
		client:        client,
		resolver:      resolver,
		tracker:       deps.DependencyTracker,
		logger:        deps.Logger,
		now:           deps.Now,
		upstreamAlias: aliasEnabled,
		upstreamHosts: client.Allowlist(),
	}, nil
}
