package goproxy

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/malware"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

func init() { adapter.Register("goproxy", Factory) }

// Factory builds the goproxy adapter from its RegistryConfig + shared Deps.
// The validation chain supports min-publication-age, cve-check (mapped to OSV's
// "Go" ecosystem) and malware-scan; the retrieval chain supports
// cve-check-retrieval, the local-disk/s3 caches and the terminal
// upstream-registry (which stashes the *Info in ctx.Index for
// min-publication-age). The mutation chain defaults to a single NoOp so the
// PreFetch/PostFetch hook path is exercised; real mutations slot in via config.
func Factory(cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	client, err := New(cfg.Upstream, nil)
	if err != nil {
		return nil, err
	}
	storage, err := OpenStorage(context.Background(), deps.DB)
	if err != nil {
		return nil, err
	}
	denyStore, err := denylist.OpenStore(context.Background(), deps.DB)
	if err != nil {
		return nil, err
	}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("deny-list-check", denylist.Factory(denyStore))
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterValidation("malware-scan", malware.Factory)
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
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
	hooks := project.ValidationHooks{
		Prepend:   dlv.Chain[0],
		OnFailure: denylist.Recorder(denyStore, deps.Now),
	}

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	resolver := project.NewResolver(cfg.Type, reg, deps.ProjectStore, global, hooks)
	return &goproxyAdapter{
		prefix:   cfg.Prefix,
		storage:  storage,
		client:   client,
		resolver: resolver,
		tracker:  deps.DependencyTracker,
		logger:   deps.Logger,
		now:      deps.Now,
	}, nil
}
