package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
)

// recorder collects ordered events from the mutation hooks and the registry
// fetch, to assert the server's contract: PreFetch -> retrieval -> PostFetch.
type recorder struct {
	mu     sync.Mutex
	events []string
	pre    int
	post   int
}

func (r *recorder) record(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// recMutation implements pipeline.MutationMiddleware, recording hook calls.
type recMutation struct{ r *recorder }

func (recMutation) Name() string { return "recording" }
func (m recMutation) PreFetch(*pipeline.PipelineContext) error {
	m.r.pre++
	m.r.record("prefetch")
	return nil
}
func (m recMutation) PostFetch(*pipeline.PipelineContext) error {
	m.r.post++
	m.r.record("postfetch")
	return nil
}

// recRegistry implements registry.RegistryClient, recording a "fetch" event on
// tarball fetch (the retrieval step).
type recRegistry struct {
	r         *recorder
	packument *registry.Packument
	tarball   []byte
}

func (c *recRegistry) FetchPackument(context.Context, string) (*registry.Packument, error) {
	return c.packument, nil
}
func (c *recRegistry) FetchPackumentRaw(context.Context, string) ([]byte, error) {
	return nil, nil
}
func (c *recRegistry) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	c.r.record("fetch")
	return io.NopCloser(bytes.NewReader(c.tarball)), int64(len(c.tarball)), nil
}

func mutationConfig(cacheDir string, withRecording bool) *config.Config {
	cfg := &config.Config{
		Registry: "npm",
		Log:      config.Log{Level: "warn", Format: "json"},
		Validation: []config.Middleware{
			{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
		},
		Retrieval: []config.Middleware{
			{Type: "local-disk-cache", Params: yamlNode("path: " + cacheDir)},
			{Type: "upstream-registry"},
		},
	}
	if withRecording {
		// "recording" is registered below into server.New's registry via the
		// test-only hook on Server (see newTestServerWithMutation). Here we just
		// declare it so the build picks it up; the actual factory is injected.
		cfg.Mutation = []config.Middleware{{Type: "recording"}}
	}
	return cfg
}

func TestMutationHookOrderAndCount(t *testing.T) {
	dir := t.TempDir()
	rec := &recorder{}
	pack := &registry.Packument{
		Name:     "pkg",
		Versions: map[string]registry.Version{"1.0.0": {Version: "1.0.0", Dist: registry.Dist{Tarball: "u/t.tgz"}}},
		Time:     map[string]time.Time{"1.0.0": time.Now().AddDate(0, 0, -30)},
	}
	rc := &recRegistry{r: rec, packument: pack, tarball: []byte("TARBALL")}
	st := newMemStorage()

	// Build the server, then override its mutation chain with the recorder so we
	// can observe hook calls. (Same package => can set the unexported field.)
	srv, err := New(context.Background(), mutationConfig(dir, false), st, rc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	srv.mutation = pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{recMutation{r: rec}}}
	h := srv.Handler()

	rr := doRequest(t, h, http.MethodGet, "/pkg/-/1.0.0", "")
	if rr.Code != 200 {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}

	rec.mu.Lock()
	got := append([]string(nil), rec.events...)
	pre, post := rec.pre, rec.post
	rec.mu.Unlock()

	// Contract: exactly one PreFetch (before retrieval) and one PostFetch
	// (after retrieval/hash-verify), with retrieval in between.
	if pre != 1 || post != 1 {
		t.Errorf("hook counts: pre=%d post=%d, want 1/1", pre, post)
	}
	wantOrder := []string{"prefetch", "fetch", "postfetch"}
	if !equalStrings(got, wantOrder) {
		t.Errorf("event order = %v, want %v", got, wantOrder)
	}
}

// TestEmptyMutationShipsNoOp verifies that an empty mutation config results in a
// single no-op mutation middleware (v1 default).
func TestEmptyMutationShipsNoOp(t *testing.T) {
	dir := t.TempDir()
	pack := &registry.Packument{
		Versions: map[string]registry.Version{"1.0.0": {Dist: registry.Dist{Tarball: "u/t.tgz"}}},
		Time:     map[string]time.Time{"1.0.0": time.Now().AddDate(0, 0, -30)},
	}
	rc := &recRegistry{r: &recorder{}, packument: pack, tarball: []byte("B")}
	srv, err := New(context.Background(), mutationConfig(dir, false), newMemStorage(), rc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if len(srv.mutation.Chain) != 1 {
		t.Fatalf("mutation chain len = %d, want 1 (NoOp)", len(srv.mutation.Chain))
	}
	if _, ok := srv.mutation.Chain[0].(mutation.NoOp); !ok {
		t.Errorf("expected mutation.NoOp, got %T", srv.mutation.Chain[0])
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
