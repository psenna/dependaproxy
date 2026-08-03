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

// Resolver maps a project key to the Resolved pipelines for that project,
// falling back to the global pipelines when the key is unknown. Results are
// memoized in an in-process cache; Invalidate removes one entry.
type Resolver struct {
	registryType string
	reg          *pipeline.Registry
	store        Store
	global       *Resolved
	cache        sync.Map // string -> *Resolved
}

// NewResolver returns a Resolver for one registry type. The empty key maps to
// global (the pre-project default path) and is never re-read from the store.
func NewResolver(registryType string, reg *pipeline.Registry, store Store, global *Resolved) *Resolver {
	r := &Resolver{registryType: registryType, reg: reg, store: store, global: global}
	r.cache.Store("", global)
	return r
}

// Resolve returns the pipelines for projectKey, building and caching them on
// first use. An unknown key falls back to the global pipelines (also cached, so
// the store is read at most once per key).
func (r *Resolver) Resolve(projectKey string) (*Resolved, error) {
	if v, ok := r.cache.Load(projectKey); ok {
		return v.(*Resolved), nil
	}
	cfg, err := r.store.Get(context.Background(), projectKey)
	if errors.Is(err, ErrProjectNotFound) {
		actual, _ := r.cache.LoadOrStore(projectKey, r.global)
		return actual.(*Resolved), nil
	}
	if err != nil {
		return nil, err
	}
	rp, err := r.build(cfg)
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
// project does not override from the global pipelines.
func (r *Resolver) build(cfg ProjectConfig) (*Resolved, error) {
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
	return rp, nil
}
