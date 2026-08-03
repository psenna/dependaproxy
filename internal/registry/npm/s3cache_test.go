package npm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// TestS3CacheTrustFlow runs the full npm trust flow against a real MinIO/S3:
// cache miss -> fetch + verify + write-through; repeat request -> served from
// S3 (no upstream tarball fetch); tampered object -> evicted + refetched +
// re-verified (serves the correct bytes again). Skipped unless
// DP_TEST_MINIO_ENDPOINT is set (mirrors the postgres-gated pattern).
func TestS3CacheTrustFlow(t *testing.T) {
	ep := os.Getenv("DP_TEST_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("DP_TEST_MINIO_ENDPOINT not set; skipping MinIO integration test")
	}
	access, secret := os.Getenv("DP_TEST_MINIO_ACCESS_KEY"), os.Getenv("DP_TEST_MINIO_SECRET_KEY")

	mc, err := minio.New(ep, &minio.Options{Creds: credentials.NewStaticV4(access, secret, "")})
	if err != nil {
		t.Fatal(err)
	}
	bucket := fmt.Sprintf("dp-test-npm-%d", time.Now().UnixNano())
	if err := mc.MakeBucket(context.Background(), bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mc.RemoveBucket(context.Background(), bucket) })

	store := newMemStore()
	tarball := []byte("TARBALL")
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	client := &rawClient{pack: pack, raw: raw, tarball: tarball}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("s3-cache", s3cache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	s3Params := fmt.Sprintf("endpoint: %s\nbucket: %s\naccess_key: %s\nsecret_key: %s", ep, bucket, access, secret)
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "s3-cache", Params: yamlNode(s3Params)},
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
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	a := &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
	srv := newTestServer(t, a)

	// 1. First fetch: miss -> upstream -> validate -> store -> write-through to S3.
	if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != http.StatusOK || string(body) != "TARBALL" {
		t.Fatalf("first fetch: code=%d body=%q", code, body)
	}

	// 2. Second fetch: served from S3 (hash-verified); upstream tarball untouched.
	first := atomic.LoadInt32(&client.tarCalls)
	if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != http.StatusOK || string(body) != "TARBALL" {
		t.Fatalf("second fetch: code=%d body=%q", code, body)
	}
	if got := atomic.LoadInt32(&client.tarCalls); got != first {
		t.Fatalf("second fetch hit upstream (tar=%d -> %d); S3 cache should serve", first, got)
	}

	// 3. Tamper the object in S3: next fetch must evict + refetch + reverify.
	objKey := "npm/testpkg/1.0.0.bin"
	if _, err := mc.PutObject(context.Background(), bucket, objKey,
		bytes.NewReader([]byte("GARBAGE")), 7, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != http.StatusOK || string(body) != "TARBALL" {
		t.Fatalf("tampered fetch: code=%d body=%q (want 200 + re-verified bytes)", code, body)
	}
	// The evicted object was rewritten with the correct bytes.
	obj, err := mc.GetObject(context.Background(), bucket, objKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = obj.Close() }()
	rewritten, _ := io.ReadAll(obj)
	if string(rewritten) != "TARBALL" {
		t.Fatalf("after tamper+evict the S3 object should hold the verified bytes, got %q", rewritten)
	}
}
