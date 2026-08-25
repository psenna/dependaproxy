package pipeline

import (
	"errors"
	"fmt"

	"github.com/psenna/dependaproxy/internal/config"
	"gopkg.in/yaml.v3"
)

// ErrNoResolver is returned when no retrieval middleware resolved the package.
var ErrNoResolver = errors.New("pipeline: no retrieval middleware resolved the package")

// ErrRejected is wrapped by a retrieval middleware that denies a request by
// policy (e.g. a retrieval-stage CVE check). Adapters map it to 403.
var ErrRejected = errors.New("pipeline: request rejected by retrieval middleware")

// Evictor is implemented by cache retrieval middleware (localcache.Middleware).
// Resolved.Cache may be nil when the retrieval chain has no cache head.
type Evictor interface {
	Evict(ctx *PipelineContext) error
}

// --- Validation ---

// ValidationMiddleware inspects a package and may reject it. Implementations
// must be safe for concurrent use.
type ValidationMiddleware interface {
	Name() string
	Validate(ctx *PipelineContext) error
}

// ValidationFactory builds a ValidationMiddleware from its raw params node.
type ValidationFactory func(params yaml.Node) (ValidationMiddleware, error)

// ValidationError reports a validation failure from a specific middleware. It is
// returned by ValidationPipeline.Run at the exact site where validation fails so
// consumers can read the failing middleware's name without string-parsing.
type ValidationError struct {
	Middleware string
	Err        error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation %q: %s", e.Middleware, e.Err)
}
func (e *ValidationError) Unwrap() error { return e.Err }

// --- Retrieval (decorator chain) ---

// RetrievalMiddleware resolves a package. Contract:
//   - On hit: populate ctx.Tarball (and/or ctx.Packument) and return (true, nil).
//   - On miss: call next.Fetch(ctx) and return its result (write-through caches
//     persist on a downstream hit before returning).
//   - On error: return (false, err) to abort the chain.
//
// next is nil for the terminal middleware (upstream-registry); the chain is
// assembled by Registry.BuildRetrieval so each middleware wraps the next.
type RetrievalMiddleware interface {
	Name() string
	Fetch(ctx *PipelineContext) (hit bool, err error)
}

// RetrievalFactory wraps next with a new retrieval middleware built from params.
type RetrievalFactory func(params yaml.Node, next RetrievalMiddleware) (RetrievalMiddleware, error)

// --- Mutation ---

// MutationMiddleware runs before fetch (PreFetch) and after integrity
// verification (PostFetch). v1 ships a NoOp; real mutations slot in later.
type MutationMiddleware interface {
	Name() string
	PreFetch(ctx *PipelineContext) error
	PostFetch(ctx *PipelineContext) error
}

// MutationFactory builds a MutationMiddleware from its raw params node.
type MutationFactory func(params yaml.Node) (MutationMiddleware, error)

// Registry maps config `type:` strings to middleware factories. Each concrete
// middleware package exposes a Factory value; the server registers them into a
// Registry and builds the pipelines from config.
type Registry struct {
	validation map[string]ValidationFactory
	retrieval  map[string]RetrievalFactory
	mutation   map[string]MutationFactory
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		validation: map[string]ValidationFactory{},
		retrieval:  map[string]RetrievalFactory{},
		mutation:   map[string]MutationFactory{},
	}
}

// RegisterValidation registers a validation middleware factory by name.
func (r *Registry) RegisterValidation(name string, f ValidationFactory) {
	r.validation[name] = f
}

// RegisterRetrieval registers a retrieval middleware factory by name.
func (r *Registry) RegisterRetrieval(name string, f RetrievalFactory) {
	r.retrieval[name] = f
}

// RegisterMutation registers a mutation middleware factory by name.
func (r *Registry) RegisterMutation(name string, f MutationFactory) {
	r.mutation[name] = f
}

// --- Runners ---

// ValidationPipeline runs an ordered chain; the first error aborts. An empty
// chain is a no-op pass.
type ValidationPipeline struct {
	Chain []ValidationMiddleware
	// OnFailure, when non-nil, is invoked exactly once on the first failing
	// middleware with the wrapped ValidationError. It is best-effort: a failure
	// (or panic) inside the hook must never change the deny decision, so its
	// return value is ignored.
	OnFailure func(ctx *PipelineContext, err error)
}

// Find returns the first middleware in the chain named name, or (nil, false).
// Used by trusted-cache-hit paths that want to re-run a specific middleware
// (e.g. deny-list-check) without running the full chain.
func (p ValidationPipeline) Find(name string) (ValidationMiddleware, bool) {
	for _, m := range p.Chain {
		if m.Name() == name {
			return m, true
		}
	}
	return nil, false
}

// Run executes the validation chain in order.
func (p ValidationPipeline) Run(ctx *PipelineContext) error {
	for _, m := range p.Chain {
		if err := m.Validate(ctx); err != nil {
			wrapped := &ValidationError{Middleware: m.Name(), Err: err}
			if p.OnFailure != nil {
				p.OnFailure(ctx, wrapped)
			}
			return wrapped
		}
	}
	return nil
}

// RetrievalPipeline runs a decorator chain. Run resolves the package via the
// head middleware; if nothing resolves, ErrNoResolver is returned.
type RetrievalPipeline struct{ Head RetrievalMiddleware }

// Run executes the retrieval chain.
func (p RetrievalPipeline) Run(ctx *PipelineContext) error {
	if p.Head == nil {
		return ErrNoResolver
	}
	hit, err := p.Head.Fetch(ctx)
	if err != nil {
		return err
	}
	if !hit {
		return ErrNoResolver
	}
	return nil
}

// MutationPipeline runs PreFetch in order and PostFetch in order. An empty
// chain is a no-op.
type MutationPipeline struct{ Chain []MutationMiddleware }

// RunPreFetch runs every middleware's PreFetch hook in order.
func (p MutationPipeline) RunPreFetch(ctx *PipelineContext) error {
	for _, m := range p.Chain {
		if err := m.PreFetch(ctx); err != nil {
			return fmt.Errorf("mutation prefetch %q: %w", m.Name(), err)
		}
	}
	return nil
}

// RunPostFetch runs every middleware's PostFetch hook in order.
func (p MutationPipeline) RunPostFetch(ctx *PipelineContext) error {
	for _, m := range p.Chain {
		if err := m.PostFetch(ctx); err != nil {
			return fmt.Errorf("mutation postfetch %q: %w", m.Name(), err)
		}
	}
	return nil
}

// --- Builders ---

// BuildValidation builds the validation chain from config, rejecting unknown
// middleware types with a descriptive error.
func (r *Registry) BuildValidation(ms []config.Middleware) (ValidationPipeline, error) {
	chain := make([]ValidationMiddleware, 0, len(ms))
	for i, m := range ms {
		f, ok := r.validation[m.Type]
		if !ok {
			return ValidationPipeline{}, fmt.Errorf("validation[%d]: unknown middleware type %q", i, m.Type)
		}
		mw, err := f(m.Params)
		if err != nil {
			return ValidationPipeline{}, fmt.Errorf("validation[%d] %q: %w", i, m.Type, err)
		}
		chain = append(chain, mw)
	}
	return ValidationPipeline{Chain: chain}, nil
}

// noResolver is the terminal fallback in the decorator chain.
type noResolver struct{}

func (noResolver) Name() string                             { return "no-resolver" }
func (noResolver) Fetch(ctx *PipelineContext) (bool, error) { return false, ErrNoResolver }

// BuildRetrieval builds the decorator chain from config, wrapping each
// middleware around the next so the chain resolves in config order. The chain
// is built tail-first: the terminal noResolver is the innermost, and each
// configured middleware wraps the result so far.
func (r *Registry) BuildRetrieval(ms []config.Middleware) (RetrievalPipeline, error) {
	next := RetrievalMiddleware(noResolver{})
	for i := len(ms) - 1; i >= 0; i-- {
		m := ms[i]
		f, ok := r.retrieval[m.Type]
		if !ok {
			return RetrievalPipeline{}, fmt.Errorf("retrieval[%d]: unknown middleware type %q", i, m.Type)
		}
		mw, err := f(m.Params, next)
		if err != nil {
			return RetrievalPipeline{}, fmt.Errorf("retrieval[%d] %q: %w", i, m.Type, err)
		}
		next = mw
	}
	return RetrievalPipeline{Head: next}, nil
}

// BuildMutation builds the mutation chain from config, rejecting unknown types.
func (r *Registry) BuildMutation(ms []config.Middleware) (MutationPipeline, error) {
	chain := make([]MutationMiddleware, 0, len(ms))
	for i, m := range ms {
		f, ok := r.mutation[m.Type]
		if !ok {
			return MutationPipeline{}, fmt.Errorf("mutation[%d]: unknown middleware type %q", i, m.Type)
		}
		mw, err := f(m.Params)
		if err != nil {
			return MutationPipeline{}, fmt.Errorf("mutation[%d] %q: %w", i, m.Type, err)
		}
		chain = append(chain, mw)
	}
	return MutationPipeline{Chain: chain}, nil
}
