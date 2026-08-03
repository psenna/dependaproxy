package npm

import (
	"context"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/malware"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

func init() { adapter.Register("npm", Factory) }

// Factory builds the npm adapter from its RegistryConfig + shared Deps.
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
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterValidation("malware-scan", malware.Factory)
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
		// v1/v2 ship a single no-op mutation so the PreFetch/PostFetch hook
		// path is exercised; real mutations slot in via config.
		mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}
	}

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	resolver := project.NewResolver(cfg.Type, reg, deps.ProjectStore, global)
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
