package pypi

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

func init() { adapter.Register("pypi", Factory) }

// Factory builds the pypi adapter from its RegistryConfig + shared Deps.
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
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
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

	var cache evicter
	if e, ok := retrieval.Head.(evicter); ok {
		cache = e
	}

	return &pypiAdapter{
		prefix:     cfg.Prefix,
		storage:    storage,
		client:     client,
		validation: validation,
		retrieval:  retrieval,
		mutation:   mp,
		cache:      cache,
		logger:     deps.Logger,
		now:        deps.Now,
	}, nil
}
