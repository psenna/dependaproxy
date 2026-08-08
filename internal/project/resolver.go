package project

import (
	"context"
	"errors"
	"sync"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

// Resolved is a fully-built set of pipelines for one request scope (the global
// default or a project override). It is immutable after construction.
type Resolved struct {
	Validation pipeline.ValidationPipeline
	Retrieval  pipeline.RetrievalPipeline
	Mutation   pipeline.MutationPipeline
	Cache      pipeline.Evictor // nil if retrieval head is not a cache
}

// ValidationHooks are applied by the Resolver to EVERY validation pipeline it
// builds (the global default and each project override), so deny-list-check
// always runs first and failures are always recorded, regardless of whether a
// project config overrides the validation chain.
type ValidationHooks struct {
	Prepend   pipeline.ValidationMiddleware // e.g. deny-list-check; prepended if not already first
	OnFailure func(*pipeline.PipelineContext, error)
}

// Resolver maps a project key to the Resolved pipelines for that project,
// falling back to the global pipelines when the key is unknown. Results are
// memoized in an in-process cache; Invalidate removes one entry.
type Resolver struct {
	registryType string
	reg          *pipeline.Registry
	store        Store
	global       *Resolved
	hooks        ValidationHooks
	cache        sync.Map // string -> *Resolved
}

// NewResolver returns a Resolver for one registry type. The empty key maps to
// global (the pre-project default path) and is never re-read from the store.
// An optional ValidationHooks value is applied to the global pipeline now and
// to every project pipeline built later.
func NewResolver(registryType string, reg *pipeline.Registry, store Store, global *Resolved, hooks ...ValidationHooks) *Resolver {
	r := &Resolver{registryType: registryType, reg: reg, store: store, global: global}
	if len(hooks) > 0 {
		r.hooks = hooks[0]
	}
	r.applyHooks(&global.Validation) // the global is a *Resolved; mutate it
	r.cache.Store("", global)
	return r
}

// applyHooks prepends hooks.Prepend (unless the chain already starts with it)
// and sets hooks.OnFailure. It is applied to the global pipeline in NewResolver
// and to every project pipeline in build.
func (r *Resolver) applyHooks(v *pipeline.ValidationPipeline) {
	if r.hooks.Prepend != nil && (len(v.Chain) == 0 || v.Chain[0].Name() != r.hooks.Prepend.Name()) {
		v.Chain = append([]pipeline.ValidationMiddleware{r.hooks.Prepend}, v.Chain...)
	}
	if r.hooks.OnFailure != nil {
		v.OnFailure = r.hooks.OnFailure
	}
}

// Resolve returns the pipelines for projectKey, building and caching them on
// first use. An unknown key falls back to the global pipelines (also cached, so
// the store is read at most once per key). The store read is cancelled when ctx
// is done; a nil ctx is treated as context.Background().
func (r *Resolver) Resolve(ctx context.Context, projectKey string) (*Resolved, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if v, ok := r.cache.Load(projectKey); ok {
		return v.(*Resolved), nil
	}
	cfg, err := r.store.Get(ctx, projectKey)
	if errors.Is(err, ErrProjectNotFound) {
		actual, _ := r.cache.LoadOrStore(projectKey, r.global)
		return actual.(*Resolved), nil
	}
	if err != nil {
		return nil, err
	}
	rp, err := r.build(ctx, cfg)
	if err != nil {
		return nil, err
	}
	actual, _ := r.cache.LoadOrStore(projectKey, rp)
	return actual.(*Resolved), nil
}

// Invalidate drops the cached pipelines for key so the next Resolve re-reads
// the store. The empty key (the global default) is never invalidated.
func (r *Resolver) Invalidate(key string) {
	if key == "" {
		return
	}
	r.cache.Delete(key)
}

// build assembles a Resolved from a project config, inheriting any chain the
// project does not override from the global pipelines. ctx is accepted for
// forward compatibility so the Build* calls can be cancelled when they grow a
// context parameter; it is not yet used.
func (r *Resolver) build(ctx context.Context, cfg ProjectConfig) (*Resolved, error) {
	rmw, ok := cfg.Registries[r.registryType]
	if !ok {
		return r.global, nil
	}
	rp := &Resolved{}
	if len(rmw.Validation) > 0 {
		v, err := r.reg.BuildValidation(rmw.Validation)
		if err != nil {
			return nil, err
		}
		rp.Validation = v
	} else {
		rp.Validation = r.global.Validation
	}
	if len(rmw.Retrieval) > 0 {
		ret, err := r.reg.BuildRetrieval(rmw.Retrieval)
		if err != nil {
			return nil, err
		}
		rp.Retrieval = ret
		if e, ok := ret.Head.(pipeline.Evictor); ok {
			rp.Cache = e
		}
	} else {
		rp.Retrieval = r.global.Retrieval
		rp.Cache = r.global.Cache
	}
	if len(rmw.Mutation) > 0 {
		m, err := r.reg.BuildMutation(rmw.Mutation)
		if err != nil {
			return nil, err
		}
		rp.Mutation = m
	} else {
		rp.Mutation = r.global.Mutation
	}
	// Apply the hooks to whatever branch set rp.Validation (the built override
	// or the inherited global — the latter is harmless, the hooks are already
	// applied and idempotent), so project overrides can never drop the
	// deny-list check or the failure recorder.
	r.applyHooks(&rp.Validation)
	return rp, nil
}
