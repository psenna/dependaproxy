package pypi

import (
	"bytes"
	"context"
	"io"
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

// fakeDenyStoreP is a minimal in-memory denylist.Store for the trusted-cache
// re-check regression test below. Matching is exact per scope, mirroring the
// PostgresStore's strict per-scope matching.
type fakeDenyStoreP struct {
	mu      sync.Mutex
	denials map[string]string
}

func newFakeDenyStoreP() *fakeDenyStoreP { return &fakeDenyStoreP{denials: map[string]string{}} }

func (f *fakeDenyStoreP) seed(registry, name, version, sha256, projectKey, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denials[registry+"|"+name+"|"+version+"|"+sha256+"|"+projectKey] = reason
}

func (f *fakeDenyStoreP) Lookup(_ context.Context, registry, name, version, sha256, projectKey string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reason, ok := f.denials[registry+"|"+name+"|"+version+"|"+sha256+"|"+projectKey]
	return reason, ok, nil
}

func (f *fakeDenyStoreP) Record(context.Context, denylist.Denial) error { return nil }

// TestPypiDenylistBlocksTrustedCacheHit is the regression test for the H2
// deny-list half: a trust-store hit must not bypass a denial recorded after
// the artifact was originally validated. Without serveTrusted re-running
// deny-list-check, this request would be served straight from the cache with
// no validation at all.
func TestPypiDenylistBlocksTrustedCacheHit(t *testing.T) {
	dir := t.TempDir()
	fileBytes := []byte("WHEEL")
	sha, _, err := hash.Sha256Hex(bytes.NewReader(fileBytes))
	if err != nil {
		t.Fatal(err)
	}

	store := newMemStore()
	store.recs[pkey("", "testpkg", "1.0.0", wheelFile)] = Record{
		Name: "testpkg", Version: "1.0.0", Filename: wheelFile, FileType: "wheel",
		Sha256: sha, ValidatedAt: time.Now().UTC(),
	}

	deny := newFakeDenyStoreP()
	// Seeded as if the operator denylisted this exact sha256 *after* it was
	// originally validated and stored -- the scenario the trust store alone
	// cannot protect against.
	deny.seed("pypi", "testpkg", "1.0.0", sha, "", "denied after validation")

	dlMiddleware, err := denylist.Factory(deny)(yaml.Node{})
	if err != nil {
		t.Fatal(err)
	}
	global := &project.Resolved{Validation: pipeline.ValidationPipeline{Chain: []pipeline.ValidationMiddleware{dlMiddleware}}}

	proj := &Project{Name: "testpkg", Files: []File{{Filename: wheelFile, URL: "http://up/f.whl"}}}
	c := &rawClient{project: proj, file: fileBytes}
	a := newTestAdapterWithGlobal(t, "/pypi", dir, 0, c, store, global)
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/pypi/files/testpkg/1.0.0/" + wheelFile) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 {
		t.Fatalf("code=%d want 403 (trusted cache hit must re-check deny-list)", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("denied after validation")) {
		t.Errorf("body = %q, want the stored denial reason", body)
	}
}
