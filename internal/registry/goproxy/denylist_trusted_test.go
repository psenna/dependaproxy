package goproxy

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// fakeDenyStoreG is a minimal in-memory denylist.Store for the trusted-cache
// re-check regression test below. Matching is exact per scope, mirroring the
// PostgresStore's strict per-scope matching.
type fakeDenyStoreG struct {
	mu      sync.Mutex
	denials map[string]string
}

func newFakeDenyStoreG() *fakeDenyStoreG { return &fakeDenyStoreG{denials: map[string]string{}} }

func (f *fakeDenyStoreG) seed(registry, name, version, sha256, projectKey, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denials[registry+"|"+name+"|"+version+"|"+sha256+"|"+projectKey] = reason
}

func (f *fakeDenyStoreG) Lookup(_ context.Context, registry, name, version, sha256, projectKey string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reason, ok := f.denials[registry+"|"+name+"|"+version+"|"+sha256+"|"+projectKey]
	return reason, ok, nil
}

func (f *fakeDenyStoreG) Record(context.Context, denylist.Denial) error { return nil }

// TestGoproxyDenylistBlocksTrustedCacheHit is the regression test for the H2
// deny-list half: a trust-store hit must not bypass a denial recorded after
// the module was originally validated. Without serveTrusted re-running
// deny-list-check, this request would be served straight from the cache with
// no validation at all.
func TestGoproxyDenylistBlocksTrustedCacheHit(t *testing.T) {
	sha, _, err := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	if err != nil {
		t.Fatal(err)
	}

	store := newMemStore()
	store.recs[k("", testModule, testVersion)] = Record{
		ModulePath: testModule, Version: testVersion, ValidationHash: sha, ValidatedAt: time.Now().UTC(),
	}

	deny := newFakeDenyStoreG()
	// Seeded as if the operator denylisted this exact sha256 *after* it was
	// originally validated and stored -- the scenario the trust store alone
	// cannot protect against.
	deny.seed("goproxy", testModule, testVersion, sha, "", "denied after validation")

	dlMiddleware, err := denylist.Factory(deny)(yaml.Node{})
	if err != nil {
		t.Fatal(err)
	}
	global := &project.Resolved{Validation: pipeline.ValidationPipeline{Chain: []pipeline.ValidationMiddleware{dlMiddleware}}}

	a := newTestAdapterWithGlobal(t, "/goproxy", newFakeClient(), store, global)
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (trusted cache hit must re-check deny-list)", code)
	}
	if !bytes.Contains(body, []byte("denied after validation")) {
		t.Errorf("body = %q, want the stored denial reason", body)
	}
}
