package project_test

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/registry/npm"
	"gopkg.in/yaml.v3"
)

// fakeStore is an in-memory project.Store that counts Get calls.
type fakeStore struct {
	mu   sync.Mutex
	cfgs map[string]project.ProjectConfig
	gets int
}

func newFakeStore(cfgs map[string]project.ProjectConfig) *fakeStore {
	return &fakeStore{cfgs: cfgs}
}

func (s *fakeStore) Get(_ context.Context, key string) (project.ProjectConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if c, ok := s.cfgs[key]; ok {
		return c, nil
	}
	return project.ProjectConfig{}, project.ErrProjectNotFound
}
func (s *fakeStore) Put(context.Context, project.ProjectConfig) error { return nil }
func (s *fakeStore) List(context.Context) ([]project.ProjectConfig, error) {
	return nil, nil
}
func (s *fakeStore) Delete(context.Context, string) error { return nil }

func (s *fakeStore) getCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

// stubClient is a no-op npm RegistryClient; the resolver only builds pipelines,
// it never fetches, so the client is never called.
type stubClient struct{}

func (stubClient) FetchPackument(context.Context, string) (*npm.Packument, error) {
	return nil, nil
}
func (stubClient) FetchPackumentRaw(context.Context, string) ([]byte, error) { return nil, nil }
func (stubClient) FetchBytes(context.Context, string) ([]byte, error)        { return nil, nil }
func (stubClient) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, nil
}

// stubValidation is a configurable-name validation middleware used to stand in
// for the deny-list-check Prepend hook in resolver tests.
type stubValidation struct{ name string }

func (m *stubValidation) Name() string                             { return m.name }
func (m *stubValidation) Validate(*pipeline.PipelineContext) error { return nil }

// stubFactory returns a factory that always builds the given middleware.
func stubFactory(m *stubValidation) pipeline.ValidationFactory {
	return func(yaml.Node) (pipeline.ValidationMiddleware, error) { return m, nil }
}

// newEnv builds a Registry wired with the real npm middleware factories, a
// global Resolved (cve-check deny + localcache retrieval + noop mutation), and
// a fresh fake store.
func newEnv(t *testing.T) (*fakeStore, *pipeline.Registry, *project.Resolved) {
	t.Helper()
	dir := t.TempDir()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", npm.MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", npm.UpstreamFactory(stubClient{}))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
		{Type: "cve-check", Params: yamlNode("endpoint: http://osv.invalid")},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: yamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, err := reg.BuildMutation(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp}
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		global.Cache = e
	}
	return newFakeStore(map[string]project.ProjectConfig{}), reg, global
}

func TestResolveDefaultNoDB(t *testing.T) {
	store, reg, global := newEnv(t)
	r := project.NewResolver("npm", reg, store, global)

	got, err := r.Resolve("")
	if err != nil {
		t.Fatalf("resolve default: %v", err)
	}
	if got != global {
		t.Error("default key must return the pre-seeded global without touching the store")
	}
	if n := store.getCount(); n != 0 {
		t.Errorf("store.Get calls = %d, want 0 (default key is pre-cached)", n)
	}
	if _, err := r.Resolve(""); err != nil {
		t.Fatalf("resolve default again: %v", err)
	}
	if n := store.getCount(); n != 0 {
		t.Errorf("store.Get calls after repeat = %d, want 0", n)
	}
}

func TestResolveUnknownFallsBackAndCaches(t *testing.T) {
	store, reg, global := newEnv(t)
	r := project.NewResolver("npm", reg, store, global)

	got, err := r.Resolve("nope")
	if err != nil {
		t.Fatalf("resolve unknown: %v", err)
	}
	if got != global {
		t.Error("unknown key must fall back to the global Resolved")
	}
	if n := store.getCount(); n != 1 {
		t.Errorf("store.Get calls = %d, want 1", n)
	}
	if _, err := r.Resolve("nope"); err != nil {
		t.Fatalf("resolve unknown again: %v", err)
	}
	if n := store.getCount(); n != 1 {
		t.Errorf("store.Get calls after repeat = %d, want 1 (fallback cached)", n)
	}
}

func TestResolveKnownBuildsPerProject(t *testing.T) {
	store, reg, global := newEnv(t)
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {
				Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("endpoint: http://osv.invalid\nmode: warn")}},
			},
		},
	}
	r := project.NewResolver("npm", reg, store, global)

	rp, err := r.Resolve("acme")
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if rp == global {
		t.Error("acme must get a per-project Resolved, not the global")
	}
	// The project chain is a distinct Validation chain (cve-check warn) while
	// retrieval/mutation fall back to the global pipelines.
	if len(rp.Validation.Chain) != 1 {
		t.Errorf("acme validation chain len = %d, want 1", len(rp.Validation.Chain))
	}
	if rp.Retrieval.Head != global.Retrieval.Head {
		t.Error("acme retrieval must fall back to the global retrieval")
	}
	if rp.Cache != global.Cache {
		t.Error("acme cache must fall back to the global cache")
	}
	if n := store.getCount(); n != 1 {
		t.Errorf("store.Get calls = %d, want 1", n)
	}
	// Cached: the second resolve does not hit the store.
	if _, err := r.Resolve("acme"); err != nil {
		t.Fatalf("resolve acme again: %v", err)
	}
	if n := store.getCount(); n != 1 {
		t.Errorf("store.Get calls after repeat = %d, want 1", n)
	}
}

func TestResolvePerChainFallback(t *testing.T) {
	store, reg, global := newEnv(t)
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {
				Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("endpoint: http://osv.invalid\nmode: warn")}},
			},
		},
	}
	r := project.NewResolver("npm", reg, store, global)

	rp, err := r.Resolve("acme")
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if rp.Validation.Chain == nil {
		t.Error("acme validation must be newly built (project override present)")
	}
	// Only npm.validation is set: retrieval + cache must be the exact global
	// instances, mutation the exact global chain.
	if rp.Retrieval.Head != global.Retrieval.Head {
		t.Error("rp.Retrieval.Head != global.Retrieval.Head (per-chain fallback failed)")
	}
	if rp.Cache != global.Cache {
		t.Error("rp.Cache != global.Cache (per-chain fallback failed)")
	}
	if len(rp.Mutation.Chain) != len(global.Mutation.Chain) {
		t.Error("rp.Mutation must inherit the global mutation chain")
	}
}

func TestResolveMissingAdapterEntry(t *testing.T) {
	store, reg, global := newEnv(t)
	// The project only overrides the pypi registry; resolving as npm must
	// produce the global pipelines.
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"pypi": {Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("mode: warn")}}},
		},
	}
	r := project.NewResolver("npm", reg, store, global)

	got, err := r.Resolve("acme")
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if got != global {
		t.Error("a project without a npm entry must fall back to the global Resolved")
	}
}

func TestResolveHooksAppliedToGlobal(t *testing.T) {
	store, reg, global := newEnv(t)
	prepend := &stubValidation{name: "deny-list-check"}
	recorded := 0
	r := project.NewResolver("npm", reg, store, global, project.ValidationHooks{
		Prepend:   prepend,
		OnFailure: func(*pipeline.PipelineContext, error) { recorded++ },
	})

	got, err := r.Resolve("")
	if err != nil {
		t.Fatalf("resolve default: %v", err)
	}
	if len(got.Validation.Chain) == 0 || got.Validation.Chain[0] != prepend {
		t.Errorf("global validation chain[0] = %v, want the prepend middleware", got.Validation.Chain)
	}
	if got.Validation.OnFailure == nil {
		t.Error("global OnFailure is nil, want the hooks OnFailure")
	}
	if recorded != 0 {
		t.Errorf("recorded = %d, want 0 (hook not invoked during resolve)", recorded)
	}
}

func TestResolveHooksAppliedToProjectOverride(t *testing.T) {
	store, reg, global := newEnv(t)
	prepend := &stubValidation{name: "deny-list-check"}
	reg.RegisterValidation("deny-list-check", stubFactory(prepend))
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {
				Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("endpoint: http://osv.invalid\nmode: warn")}},
			},
		},
	}
	onFailure := func(*pipeline.PipelineContext, error) {}
	r := project.NewResolver("npm", reg, store, global, project.ValidationHooks{
		Prepend:   prepend,
		OnFailure: onFailure,
	})

	rp, err := r.Resolve("acme")
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if rp == global {
		t.Error("acme must get a per-project Resolved, not the global")
	}
	if len(rp.Validation.Chain) != 2 {
		t.Fatalf("acme validation chain len = %d, want 2 (prepend + cve-check)", len(rp.Validation.Chain))
	}
	if rp.Validation.Chain[0] != prepend {
		t.Errorf("chain[0] = %v, want the prepend middleware (project override must not drop it)", rp.Validation.Chain[0])
	}
	if rp.Validation.OnFailure == nil {
		t.Error("acme OnFailure is nil, want the hooks OnFailure")
	}
}

func TestResolveHooksIdempotentWhenAlreadyFirst(t *testing.T) {
	store, reg, global := newEnv(t)
	prepend := &stubValidation{name: "deny-list-check"}
	reg.RegisterValidation("deny-list-check", stubFactory(prepend))
	// The project override already lists deny-list-check first.
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {
				Validation: []config.Middleware{
					{Type: "deny-list-check"},
					{Type: "cve-check", Params: yamlNode("endpoint: http://osv.invalid\nmode: warn")},
				},
			},
		},
	}
	r := project.NewResolver("npm", reg, store, global, project.ValidationHooks{
		Prepend:   prepend,
		OnFailure: func(*pipeline.PipelineContext, error) {},
	})

	rp, err := r.Resolve("acme")
	if err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if len(rp.Validation.Chain) != 2 {
		t.Errorf("acme validation chain len = %d, want 2 (no duplicate prepend)", len(rp.Validation.Chain))
	}
	if rp.Validation.Chain[0] != prepend {
		t.Errorf("chain[0] = %v, want the prepend middleware", rp.Validation.Chain[0])
	}
	if rp.Validation.OnFailure == nil {
		t.Error("acme OnFailure is nil, want the hooks OnFailure")
	}
}

func TestInvalidate(t *testing.T) {
	store, reg, global := newEnv(t)
	store.cfgs["acme"] = project.ProjectConfig{
		Key: "acme",
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("mode: warn")}}},
		},
	}
	r := project.NewResolver("npm", reg, store, global)

	if _, err := r.Resolve("acme"); err != nil {
		t.Fatalf("resolve acme: %v", err)
	}
	if n := store.getCount(); n != 1 {
		t.Fatalf("store.Get calls = %d, want 1", n)
	}
	// Resolving again is served from the cache.
	if _, err := r.Resolve("acme"); err != nil {
		t.Fatalf("resolve acme again: %v", err)
	}
	if n := store.getCount(); n != 1 {
		t.Fatalf("store.Get calls after cached resolve = %d, want 1", n)
	}
	// Invalidate drops the cache entry; the next resolve re-reads the store.
	r.Invalidate("acme")
	if _, err := r.Resolve("acme"); err != nil {
		t.Fatalf("resolve acme after invalidate: %v", err)
	}
	if n := store.getCount(); n != 2 {
		t.Fatalf("store.Get calls after invalidate = %d, want 2", n)
	}
	// Invalidate("") is a no-op; the cached entry survives.
	r.Invalidate("")
	if _, err := r.Resolve("acme"); err != nil {
		t.Fatalf("resolve acme after empty invalidate: %v", err)
	}
	if n := store.getCount(); n != 2 {
		t.Fatalf("store.Get calls after empty invalidate = %d, want 2", n)
	}
}
