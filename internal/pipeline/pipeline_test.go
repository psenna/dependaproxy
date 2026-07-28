package pipeline

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
	"gopkg.in/yaml.v3"
)

// --- fakes ---

type fakeValidation struct {
	name  string
	calls *[]string
	err   error
}

func (f fakeValidation) Name() string { return f.name }
func (f fakeValidation) Validate(ctx *PipelineContext) error {
	*f.calls = append(*f.calls, f.name)
	return f.err
}

func valFactory(name string, calls *[]string, err error) ValidationFactory {
	return func(_ yaml.Node) (ValidationMiddleware, error) {
		return fakeValidation{name: name, calls: calls, err: err}, nil
	}
}

// fakeCache is a retrieval middleware that hits if ctx.Tarball != nil; otherwise
// it calls next (write-through on a downstream hit) and records its name.
type fakeCache struct {
	name      string
	calls     *[]string
	cached    *bool
	next      RetrievalMiddleware
	hitOnCall bool // if true, resolve itself (simulate a cache hit)
}

func (f fakeCache) Name() string { return f.name }
func (f fakeCache) Fetch(ctx *PipelineContext) (bool, error) {
	*f.calls = append(*f.calls, f.name)
	if f.hitOnCall {
		ctx.Tarball = &Tarball{Bytes: []byte("cached")}
		return true, nil
	}
	hit, err := f.next.Fetch(ctx)
	if hit && err == nil {
		*f.cached = true // write-through
	}
	return hit, err
}

// fakeUpstream is the terminal retrieval middleware; it populates ctx.Tarball.
type fakeUpstream struct {
	name  string
	calls *[]string
	err   error
}

func (f fakeUpstream) Name() string { return f.name }
func (f fakeUpstream) Fetch(ctx *PipelineContext) (bool, error) {
	*f.calls = append(*f.calls, f.name)
	if f.err != nil {
		return false, f.err
	}
	ctx.Tarball = &Tarball{Bytes: []byte("upstream-bytes")}
	return true, nil
}

func upstreamFactory(name string, calls *[]string, err error) RetrievalFactory {
	return func(_ yaml.Node, next RetrievalMiddleware) (RetrievalMiddleware, error) {
		return fakeUpstream{name: name, calls: calls, err: err}, nil
	}
}

func cacheFactory(name string, calls *[]string, cached *bool) RetrievalFactory {
	return func(_ yaml.Node, next RetrievalMiddleware) (RetrievalMiddleware, error) {
		return fakeCache{name: name, calls: calls, cached: cached, next: next}, nil
	}
}

func mws(types ...string) []config.Middleware {
	out := make([]config.Middleware, len(types))
	for i, t := range types {
		out[i] = config.Middleware{Type: t, Params: yaml.Node{}}
	}
	return out
}

// --- validation ---

func TestValidationOrderingAndShortCircuit(t *testing.T) {
	var calls []string
	r := NewRegistry()
	r.RegisterValidation("v1", valFactory("v1", &calls, nil))
	r.RegisterValidation("v2", valFactory("v2", &calls, errors.New("rejected")))
	r.RegisterValidation("v3", valFactory("v3", &calls, nil))

	p, err := r.BuildValidation(mws("v1", "v2", "v3"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = p.Run(NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0"))
	if err == nil || err.Error() != `validation "v2": rejected` {
		t.Fatalf("err = %v", err)
	}
	if len(calls) != 2 || calls[0] != "v1" || calls[1] != "v2" {
		t.Errorf("calls = %v, want [v1 v2] (v3 short-circuited)", calls)
	}
}

func TestValidationEmptyNoop(t *testing.T) {
	r := NewRegistry()
	p, err := r.BuildValidation(nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := p.Run(NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0")); err != nil {
		t.Fatalf("empty validation should pass, got %v", err)
	}
}

func TestBuildValidationUnknownType(t *testing.T) {
	r := NewRegistry()
	_, err := r.BuildValidation(mws("does-not-exist"))
	if err == nil {
		t.Fatal("want error for unknown validation type")
	}
	if !strings.Contains(err.Error(), "unknown middleware type") {
		t.Errorf("err = %v", err)
	}
}

// --- retrieval ---

func TestRetrievalDecoratorWriteThrough(t *testing.T) {
	var calls []string
	cached := false
	r := NewRegistry()
	r.RegisterRetrieval("cache", cacheFactory("cache", &calls, &cached))
	r.RegisterRetrieval("upstream", upstreamFactory("upstream", &calls, nil))

	p, err := r.BuildRetrieval(mws("cache", "upstream"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx := NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0")
	if err := p.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	// cache tried first (miss), then upstream resolved; cache wrote through.
	if len(calls) != 2 || calls[0] != "cache" || calls[1] != "upstream" {
		t.Errorf("calls = %v, want [cache upstream]", calls)
	}
	if !cached {
		t.Error("cache did not write-through on downstream hit")
	}
	if string(ctx.Tarball.Bytes) != "upstream-bytes" {
		t.Errorf("tarball = %q", ctx.Tarball.Bytes)
	}
}

func TestRetrievalCacheHitSkipsUpstream(t *testing.T) {
	var calls []string
	cached := false
	r := NewRegistry()
	r.RegisterRetrieval("cache", func(_ yaml.Node, next RetrievalMiddleware) (RetrievalMiddleware, error) {
		return fakeCache{name: "cache", calls: &calls, cached: &cached, next: next, hitOnCall: true}, nil
	})
	r.RegisterRetrieval("upstream", upstreamFactory("upstream", &calls, nil))

	p, err := r.BuildRetrieval(mws("cache", "upstream"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx := NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0")
	if err := p.Run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(calls) != 1 || calls[0] != "cache" {
		t.Errorf("calls = %v, want [cache] only (upstream skipped)", calls)
	}
	if string(ctx.Tarball.Bytes) != "cached" {
		t.Errorf("tarball = %q", ctx.Tarball.Bytes)
	}
}

func TestRetrievalEmptyNoResolver(t *testing.T) {
	r := NewRegistry()
	p, err := r.BuildRetrieval(nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = p.Run(NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0"))
	if !errors.Is(err, ErrNoResolver) {
		t.Fatalf("err = %v, want ErrNoResolver", err)
	}
}

func TestRetrievalUpstreamErrorAborts(t *testing.T) {
	var calls []string
	wantErr := errors.New("upstream down")
	r := NewRegistry()
	r.RegisterRetrieval("cache", cacheFactory("cache", &calls, new(bool)))
	r.RegisterRetrieval("upstream", upstreamFactory("upstream", &calls, wantErr))
	p, err := r.BuildRetrieval(mws("cache", "upstream"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = p.Run(NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestBuildRetrievalUnknownType(t *testing.T) {
	r := NewRegistry()
	_, err := r.BuildRetrieval(mws("nope"))
	if err == nil || !strings.Contains(err.Error(), "unknown middleware type") {
		t.Fatalf("err = %v", err)
	}
}

// --- mutation ---

type fakeMutation struct {
	name      string
	pre, post *[]string
	preErr    error
}

func (f fakeMutation) Name() string { return f.name }
func (f fakeMutation) PreFetch(*PipelineContext) error {
	*f.pre = append(*f.pre, f.name)
	return f.preErr
}
func (f fakeMutation) PostFetch(*PipelineContext) error {
	*f.post = append(*f.post, f.name)
	return nil
}

func TestMutationPipelineOrder(t *testing.T) {
	var pre, post []string
	r := NewRegistry()
	r.RegisterMutation("m", func(_ yaml.Node) (MutationMiddleware, error) {
		return fakeMutation{name: "m", pre: &pre, post: &post}, nil
	})
	p, err := r.BuildMutation(mws("m", "m"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx := NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0")
	if err := p.RunPreFetch(ctx); err != nil {
		t.Fatalf("pre: %v", err)
	}
	if err := p.RunPostFetch(ctx); err != nil {
		t.Fatalf("post: %v", err)
	}
	if len(pre) != 2 || pre[0] != "m" || pre[1] != "m" {
		t.Errorf("pre = %v", pre)
	}
	if len(post) != 2 {
		t.Errorf("post = %v", post)
	}
}

func TestMutationEmptyNoop(t *testing.T) {
	r := NewRegistry()
	p, err := r.BuildMutation(nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx := NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0")
	if err := p.RunPreFetch(ctx); err != nil {
		t.Fatalf("pre: %v", err)
	}
	if err := p.RunPostFetch(ctx); err != nil {
		t.Fatalf("post: %v", err)
	}
}
