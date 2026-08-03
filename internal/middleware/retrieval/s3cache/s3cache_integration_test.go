package s3cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

// testMinioOptions reads the MinIO/S3 connection from the environment and skips
// the test when unset (mirrors the DP_TEST_PG_DSN pattern for postgres).
func testMinioOptions(t *testing.T) Options {
	t.Helper()
	ep := os.Getenv("DP_TEST_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("DP_TEST_MINIO_ENDPOINT not set; skipping MinIO integration test")
	}
	return Options{
		Endpoint:  ep,
		Bucket:    "dp-test", // placeholder; newIntegrationBackend creates a unique bucket
		AccessKey: os.Getenv("DP_TEST_MINIO_ACCESS_KEY"),
		SecretKey: os.Getenv("DP_TEST_MINIO_SECRET_KEY"),
	}
}

// newIntegrationBackend builds a Backend against a fresh, unique bucket that is
// removed at test cleanup.
func newIntegrationBackend(t *testing.T, basePath string) *Backend {
	t.Helper()
	o := testMinioOptions(t)
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	bucket := fmt.Sprintf("dp-test-%d", time.Now().UnixNano())
	exists, err := b.client.BucketExists(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err := b.client.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = b.client.RemoveBucket(context.Background(), bucket) })
	return NewWithClient(b.client, bucket, basePath)
}

// nextStub is a fake retrieval middleware that sets ctx.Tarball and counts calls.
type nextStub struct {
	calls int32
	data  []byte
}

func (n *nextStub) Name() string { return "next" }
func (n *nextStub) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	atomic.AddInt32(&n.calls, 1)
	ctx.Tarball = &pipeline.Tarball{Bytes: n.data}
	return true, nil
}

func TestMinioBackendRoundTrip(t *testing.T) {
	backend := newIntegrationBackend(t, "")
	key := "npm/express/4.18.0.bin"

	if err := backend.Put(key, []byte("TARBALL")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := backend.Get(key)
	if err != nil || string(got) != "TARBALL" {
		t.Fatalf("get: got %q err %v", got, err)
	}
	if _, err := backend.Get("npm/missing/1.0.0.bin"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key should be os.ErrNotExist, got %v", err)
	}
	if err := backend.Delete(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := backend.Get(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after delete the key should be gone, got %v", err)
	}
}

func TestMinioBackendBasePath(t *testing.T) {
	backend := newIntegrationBackend(t, "dp-cache")
	if err := backend.Put("npm/express/4.18.0.bin", []byte("T")); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := backend.Get("npm/express/4.18.0.bin")
	if err != nil || string(got) != "T" {
		t.Fatalf("get via base path: got %q err %v", got, err)
	}
}

func TestMinioMiddlewareWriteThroughAndHit(t *testing.T) {
	backend := newIntegrationBackend(t, "")
	n := &nextStub{data: []byte("TARBALL")}
	m := localcache.NewNamedBackend("s3-cache", backend, n)

	c := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "express", Version: "4.18.0", ArtifactID: ""}
	if hit, err := m.Fetch(c); err != nil || !hit {
		t.Fatalf("first fetch: hit=%v err=%v", hit, err)
	}
	if n.calls != 1 {
		t.Fatalf("first fetch should call next once, got %d", n.calls)
	}

	// A fresh middleware over the same backend serves the hit without calling next.
	m2 := localcache.NewNamedBackend("s3-cache", backend, &nextStub{data: []byte("SHOULD-NOT-USE")})
	c2 := &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "express", Version: "4.18.0", ArtifactID: ""}
	if hit, err := m2.Fetch(c2); err != nil || !hit {
		t.Fatalf("second fetch: hit=%v err=%v", hit, err)
	}
	if string(c2.Tarball.Bytes) != "TARBALL" {
		t.Fatalf("cache hit served %q want TARBALL", c2.Tarball.Bytes)
	}
	if err := m2.Evict(c2); err != nil {
		t.Fatalf("evict: %v", err)
	}
	if _, err := backend.Get("npm/express/4.18.0.bin"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evict should remove the object, got %v", err)
	}
}
