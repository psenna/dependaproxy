package goproxy

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

func init() { adapter.Register("goproxy", Factory) }

// Factory builds the goproxy adapter from its RegistryConfig + shared Deps.
// v1 ships an EMPTY validation chain (validation middlewares land in #75) and
// the terminal upstream-registry retrieval only (no local/s3 cache — #75). The
// mutation chain defaults to a single NoOp so the PreFetch/PostFetch hook path
// is exercised; real mutations slot in via config.
func Factory(cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	client, err := New(cfg.Upstream, nil)
	if err != nil {
		return nil, err
	}
	storage, err := OpenStorage(context.Background(), deps.DB)
	if err != nil {
		return nil, err
	}

	reg := pipeline.NewRegistry()
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

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	resolver := project.NewResolver(cfg.Type, reg, deps.ProjectStore, global)
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
