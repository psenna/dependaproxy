package localcache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func ctx(version, artifactID string) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "express", Version: version, ArtifactID: artifactID}
}

func TestMissWritesThenHits(t *testing.T) {
	dir := t.TempDir()
	n := &nextStub{data: []byte("TARBALL")}
	m := New(dir, n)

	c := ctx("4.18.0", "")
	if hit, err := m.Fetch(c); err != nil || !hit {
		t.Fatalf("first fetch: hit=%v err=%v", hit, err)
	}
	if n.calls != 1 {
		t.Errorf("next calls = %d want 1", n.calls)
	}
	path := filepath.Join(dir, "npm", "express", "4.18.0.bin")
	if _, err := os.ReadFile(path); err != nil { //nolint:gosec // G304: path under t.TempDir()
		t.Fatalf("cache file not written: %v", err)
	}

	m2 := New(dir, &nextStub{data: []byte("SHOULD-NOT-USE")})
	c2 := ctx("4.18.0", "")
	if hit, err := m2.Fetch(c2); err != nil || !hit {
		t.Fatalf("second fetch: hit=%v err=%v", hit, err)
	}
	if string(c2.Tarball.Bytes) != "TARBALL" {
		t.Errorf("cache hit served %q want TARBALL", c2.Tarball.Bytes)
	}
}

func TestArtifactIDKeying(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, &nextStub{data: []byte("B")})
	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "pypi", PkgName: "numpy", Version: "1.0.0", ArtifactID: "numpy-1.0.0-py3-none-any.whl"}
	if _, err := m.Fetch(c); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	path := filepath.Join(dir, "pypi", "numpy", "1.0.0", "numpy-1.0.0-py3-none-any.whl.bin")
	if _, err := os.ReadFile(path); err != nil { //nolint:gosec // G304: path under t.TempDir()
		t.Fatalf("artifactID cache file not at %s: %v", path, err)
	}
}

func TestScopedNamePath(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, &nextStub{data: []byte("B")})
	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "@scope/pkg", Version: "1.0.0", ArtifactID: ""}
	if _, err := m.Fetch(c); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	path := filepath.Join(dir, "npm", "@scope", "pkg", "1.0.0.bin")
	if _, err := os.ReadFile(path); err != nil { //nolint:gosec // G304: path under t.TempDir()
		t.Fatalf("scoped cache file not at %s: %v", path, err)
	}
}

func TestEvictRemovesFile(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, &nextStub{data: []byte("B")})
	c := ctx("1.0.0", "")
	if _, err := m.Fetch(c); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if err := m.Evict(c); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if err := m.Evict(c); err != nil {
		t.Fatalf("evict idempotent: %v", err)
	}
}

func TestNoNextReturnsNoResolver(t *testing.T) {
	dir := t.TempDir()
	m := New(dir, nil)
	_, err := m.Fetch(ctx("9.9.9", ""))
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
			if _, err := m.Fetch(ctx("2.0.0", "")); err != nil {
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
	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "../escape", Version: "1.0.0", ArtifactID: ""}
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

// memBackend is an in-process CacheBackend for tests.
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (b *memBackend) Get(ctx context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return d, nil
}
func (b *memBackend) Put(ctx context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[key] = append([]byte(nil), data...)
	return nil
}
func (b *memBackend) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, key)
	return nil
}

// TestBackendAgnostic proves the middleware serves/write-through/evicts through
// any CacheBackend (the S3 backend plugs in here), using the derived key.
func TestBackendAgnostic(t *testing.T) {
	backend := newMemBackend()
	n := &nextStub{data: []byte("TARBALL")}
	m := NewBackend(backend, n)

	c := ctx("4.18.0", "")
	if hit, err := m.Fetch(c); err != nil || !hit {
		t.Fatalf("fetch: hit=%v err=%v", hit, err)
	}
	key := "npm/express/4.18.0.bin"
	if _, ok := backend.data[key]; !ok {
		t.Fatalf("backend should hold the artifact under the derived key %q", key)
	}

	// A fresh middleware over the same backend serves the hit without calling next.
	m2 := NewBackend(backend, &nextStub{data: []byte("SHOULD-NOT-USE")})
	c2 := ctx("4.18.0", "")
	if hit, err := m2.Fetch(c2); err != nil || !hit {
		t.Fatalf("second fetch: hit=%v err=%v", hit, err)
	}
	if string(c2.Tarball.Bytes) != "TARBALL" {
		t.Fatalf("cache hit served %q want TARBALL", c2.Tarball.Bytes)
	}
	if err := m2.Evict(c2); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, ok := backend.data[key]; ok {
		t.Fatal("evict should remove the key from the backend")
	}
}

// ctxMarker is a context value used to prove the request context reaches the
// backend (the middleware must thread ctx.Ctx through, not context.Background()).
type ctxMarker struct{}

// ctxRecordingBackend records the context received by each method.
type ctxRecordingBackend struct {
	mu     sync.Mutex
	data   map[string][]byte
	putCtx context.Context
	delCtx context.Context
}

func newCtxRecordingBackend() *ctxRecordingBackend {
	return &ctxRecordingBackend{data: map[string][]byte{}}
}

func (b *ctxRecordingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return d, nil
}
func (b *ctxRecordingBackend) Put(ctx context.Context, key string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.putCtx = ctx
	b.data[key] = append([]byte(nil), data...)
	return nil
}
func (b *ctxRecordingBackend) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.delCtx = ctx
	delete(b.data, key)
	return nil
}

func TestFetchPassesContextToBackend(t *testing.T) {
	backend := newCtxRecordingBackend()
	m := NewBackend(backend, &nextStub{data: []byte("TARBALL")})

	reqCtx := context.WithValue(context.Background(), ctxMarker{}, "marker")
	c := &pipeline.PipelineContext{Ctx: reqCtx, Registry: "npm", PkgName: "express", Version: "4.18.0", ArtifactID: ""}
	if hit, err := m.Fetch(c); err != nil || !hit {
		t.Fatalf("fetch: hit=%v err=%v", hit, err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.putCtx == nil {
		t.Fatal("Put should have received the request context")
	}
	if v, _ := backend.putCtx.Value(ctxMarker{}).(string); v != "marker" {
		t.Fatalf("Put ctx marker = %q want %q", v, "marker")
	}
}

func TestEvictPassesContextToBackend(t *testing.T) {
	backend := newCtxRecordingBackend()
	m := NewBackend(backend, &nextStub{data: []byte("B")})
	if _, err := m.Fetch(ctx("1.0.0", "")); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	reqCtx := context.WithValue(context.Background(), ctxMarker{}, "marker")
	c := &pipeline.PipelineContext{Ctx: reqCtx, Registry: "npm", PkgName: "express", Version: "1.0.0", ArtifactID: ""}
	if err := m.Evict(c); err != nil {
		t.Fatalf("evict: %v", err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.delCtx == nil {
		t.Fatal("Delete should have received the request context")
	}
	if v, _ := backend.delCtx.Value(ctxMarker{}).(string); v != "marker" {
		t.Fatalf("Delete ctx marker = %q want %q", v, "marker")
	}
}

// blockingPutBackend blocks Put until the context is cancelled, recording the
// context error it observed.
type blockingPutBackend struct {
	mu       sync.Mutex
	data     map[string][]byte
	putCalls int32
	putErr   error
}

func (b *blockingPutBackend) Get(ctx context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return d, nil
}
func (b *blockingPutBackend) Put(ctx context.Context, key string, data []byte) error {
	atomic.AddInt32(&b.putCalls, 1)
	<-ctx.Done()
	err := ctx.Err()
	b.mu.Lock()
	b.putErr = err
	b.mu.Unlock()
	return err
}
func (b *blockingPutBackend) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, key)
	return nil
}

func TestFetchCancelledAbortsBackendPut(t *testing.T) {
	backend := &blockingPutBackend{data: map[string][]byte{}}
	m := NewBackend(backend, &nextStub{data: []byte("TARBALL")})

	reqCtx, cancel := context.WithCancel(context.Background())
	c := &pipeline.PipelineContext{Ctx: reqCtx, Registry: "npm", PkgName: "express", Version: "4.18.0", ArtifactID: ""}
	done := make(chan struct{})
	go func() {
		_, _ = m.Fetch(c)
		close(done)
	}()

	// Wait until the write-through Put is blocked on the context, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&backend.putCalls) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadInt32(&backend.putCalls) == 0 {
		t.Fatal("write-through Put was never reached")
	}
	cancel()
	<-done

	backend.mu.Lock()
	defer backend.mu.Unlock()
	if !errors.Is(backend.putErr, context.Canceled) {
		t.Fatalf("Put err = %v want context.Canceled", backend.putErr)
	}
}
