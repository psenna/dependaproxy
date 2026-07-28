package localcache

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// nextStub is a fake retrieval middleware that sets ctx.Tarball and counts calls.
type nextStub struct {
	calls int32
	data  []byte
	err   error
}

func (n *nextStub) Name() string { return "next" }
func (n *nextStub) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	atomic.AddInt32(&n.calls, 1)
	if n.err != nil {
		return false, n.err
	}
	ctx.Tarball = &pipeline.Tarball{Bytes: n.data}
	return true, nil
}

func ctx(version string) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "express", Version: version}
}

func TestMissWritesThenHits(t *testing.T) {
	dir := t.TempDir()
	n := &nextStub{data: []byte("TARBALL")}
	m := New(dir, n)

	c := ctx("4.18.0")
	if hit, err := m.Fetch(c); err != nil || !hit {
		t.Fatalf("first fetch: hit=%v err=%v", hit, err)
	}
	if n.calls != 1 {
		t.Errorf("next calls = %d want 1", n.calls)
	}
	if string(c.Tarball.Bytes) != "TARBALL" {
		t.Errorf("tarball = %q", c.Tarball.Bytes)
	}
	path := filepath.Join(dir, "npm", "express", "4.18.0.tgz")
	if _, err := os.ReadFile(path); err != nil { //nolint:gosec // G304: path under t.TempDir()
		t.Fatalf("cache file not written: %v", err)
	}

	// Second fetch hits the cache; a fresh next with different data is NOT used.
	m2 := New(dir, &nextStub{data: []byte("SHOULD-NOT-USE")})
	c2 := ctx("4.18.0")
	if hit, err := m2.Fetch(c2); err != nil || !hit {
		t.Fatalf("second fetch: hit=%v err=%v", hit, err)
	}
	if string(c2.Tarball.Bytes) != "TARBALL" {
		t.Errorf("cache hit served %q want TARBALL", c2.Tarball.Bytes)
	}
}

func TestScopedNamePath(t *testing.T) {
	dir := t.TempDir()
	n := &nextStub{data: []byte("B")}
	m := New(dir, n)
	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "@scope/pkg", Version: "1.0.0"}
	if _, err := m.Fetch(c); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	path := filepath.Join(dir, "npm", "@scope", "pkg", "1.0.0.tgz")
	if _, err := os.ReadFile(path); err != nil { //nolint:gosec // G304: path under t.TempDir()
		t.Fatalf("scoped cache file not at %s: %v", path, err)
	}
}

func TestEvictRemovesFile(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, &nextStub{data: []byte("B")})
	c := ctx("1.0.0")
	if _, err := m.Fetch(c); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if err := m.Evict(c); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if err := m.Evict(c); err != nil { // idempotent
		t.Fatalf("evict idempotent: %v", err)
	}
}

func TestNoNextReturnsNoResolver(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, nil)
	_, err := m.Fetch(ctx("9.9.9"))
	if err != pipeline.ErrNoResolver {
		t.Fatalf("err = %v want ErrNoResolver", err)
	}
}

func TestConcurrentFetchSameKeyCallsNextOnce(t *testing.T) {
	dir := t.TempDir()
	n := &nextStub{data: []byte("B")}
	m := New(dir, n)
	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Fetch(ctx("2.0.0")); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent fetch: %v", err)
	}
	if n.calls != 1 {
		t.Errorf("next calls = %d want 1 (per-key lock serializes)", n.calls)
	}
}

func TestRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, &nextStub{data: []byte("B")})
	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "../escape", Version: "1.0.0"}
	if _, err := m.Fetch(c); err == nil {
		t.Fatal("want error for traversal package name")
	}
}

func TestFactoryEmpty(t *testing.T) {
	mw, err := Factory(yaml.Node{}, nil)
	if err != nil {
		t.Fatalf("factory empty: %v", err)
	}
	if mw.Name() != "local-disk-cache" {
		t.Errorf("name = %q", mw.Name())
	}
}
