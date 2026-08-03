package s3cache

import (
	"testing"

	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"gopkg.in/yaml.v3"
)

func TestNewRequiresEndpointAndBucket(t *testing.T) {
	if _, err := New(Options{Bucket: "b"}); err == nil {
		t.Fatal("endpoint is required")
	}
	if _, err := New(Options{Endpoint: "minio:9000"}); err == nil {
		t.Fatal("bucket is required")
	}
}

func TestObjectKey(t *testing.T) {
	b := NewWithClient(nil, "bucket", "")
	if got := b.objectKey("npm/express/4.18.0.bin"); got != "npm/express/4.18.0.bin" {
		t.Fatalf("no basePath: got %q", got)
	}
	b2 := NewWithClient(nil, "bucket", "dp-cache/")
	if got := b2.objectKey("npm/express/4.18.0.bin"); got != "dp-cache/npm/express/4.18.0.bin" {
		t.Fatalf("with basePath: got %q", got)
	}
}

func TestFactoryDecodesParamsAndNamesS3(t *testing.T) {
	var n yaml.Node
	if err := n.Encode(map[string]any{
		"endpoint": "minio:9000", "bucket": "cache", "access_key": "k", "secret_key": "s",
	}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(n, nil)
	if err != nil {
		t.Fatalf("factory should decode valid params: %v", err)
	}
	lm, ok := mw.(*localcache.Middleware)
	if !ok {
		t.Fatalf("factory should return the shared cache middleware, got %T", mw)
	}
	if lm.Name() != "s3-cache" {
		t.Fatalf("middleware name = %q want s3-cache", lm.Name())
	}
}
