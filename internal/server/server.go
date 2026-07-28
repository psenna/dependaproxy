package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/log"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/upstreamregistry"
	"github.com/psenna/dependaproxy/internal/middleware/validation/minpublicationage"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
	"github.com/psenna/dependaproxy/internal/storage"
)

// evicter is implemented by cache middleware that can drop a cached artifact
// when it fails integrity verification. localcache.Middleware satisfies it.
type evicter interface {
	Evict(ctx *pipeline.PipelineContext) error
}

// Server wires the configured pipelines, storage, and registry client and
// serves the npm-compatible proxy routes.
type Server struct {
	cfg        *config.Config
	storage    storage.Storage
	reg        registry.RegistryClient
	validation pipeline.ValidationPipeline
	retrieval  pipeline.RetrievalPipeline
	mutation   pipeline.MutationPipeline
	cache      evicter // nil if no cache middleware is configured
	logger     *slog.Logger
	now        func() time.Time
}

// New builds a Server from config, an open Storage, and a registry client.
func New(ctx context.Context, cfg *config.Config, st storage.Storage, rc registry.RegistryClient) (*Server, error) {
	logger := log.New(cfg.Log.Format, cfg.Log.Level)

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", minpublicationage.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", upstreamregistry.Factory(rc))
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
	// v1 ships a single no-op mutation so the PreFetch/PostFetch hook path is
	// exercised; a future real mutation middleware slots in via config.
	if len(cfg.Mutation) == 0 {
		mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}
	}

	var cache evicter
	if e, ok := retrieval.Head.(evicter); ok {
		cache = e
	}

	return &Server{
		cfg:        cfg,
		storage:    st,
		reg:        rc,
		validation: validation,
		retrieval:  retrieval,
		mutation:   mp,
		cache:      cache,
		logger:     logger,
		now:        func() time.Time { return time.Now().UTC() },
	}, nil
}

// Close releases the storage backend.
func (s *Server) Close() error { return s.storage.Close() }
