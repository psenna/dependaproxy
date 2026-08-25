package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/provenance"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// contentVerifier is the adapter-test fake: it passes bundles whose payload
// contains "VALID" and rejects everything else (tampered). It also records
// the last artifactSha256Hex it was called with, so tests can assert the
// digest reaching the verifier is the real served-artifact hash (H3).
type contentVerifier struct {
	mu     sync.Mutex
	digest string
}

func (c *contentVerifier) Verify(_ context.Context, b []byte, artifactSha256Hex string) (bool, error) {
	c.mu.Lock()
	c.digest = artifactSha256Hex
	c.mu.Unlock()
	return bytes.Contains(b, []byte("VALID")), nil
}

func (c *contentVerifier) lastDigest() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.digest
}

const (
	npmValidAtt    = `{"attestations":[{"predicateType":"p","bundle":{"mediaType":"m","payload":"VALID"}}]}`
	npmTamperedAtt = `{"attestations":[{"predicateType":"p","bundle":{"mediaType":"m","payload":"TAMPERED"}}]}`
	npmEmptyAtt    = `{"attestations":[]}`
)

// npmProvenanceUpstream serves a packument with dist.attestations.url, the
// attestation document, and a tarball.
func npmProvenanceUpstream(t *testing.T, attBody string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/testpkg":
			_, _ = w.Write(packumentJSON(srv.URL+"/attestations", srv.URL+"/testpkg-1.0.0.tgz"))
		case "/attestations":
			_, _ = w.Write([]byte(attBody))
		case "/testpkg-1.0.0.tgz":
			_, _ = w.Write([]byte("TARBALL"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newProvenanceAdapter wires the npm pipeline with provenance-verify whose
// verifier is the contentVerifier fake (no real sigstore / no network). It
// returns the verifier too, so tests can inspect what it was called with.
func newProvenanceAdapter(t *testing.T, srv *httptest.Server, params string) (*npmAdapter, *memStore, *contentVerifier) {
	t.Helper()
	dir := t.TempDir()
	store := newMemStore()
	client, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cv := &contentVerifier{}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("provenance-verify", func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr provenance.Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("provenance-verify: decode params: %w", err)
			}
		}
		return provenance.New(pr, NewProvenanceSource(client), cv), nil
	})
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")}, // age gate off; only provenance gates
		{Type: "provenance-verify", Params: yamlNode(params)},
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
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	a := &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
	return a, store, cv
}

func npmProvenanceMeta(t *testing.T, store *memStore) map[string]any {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	rec, ok := store.recs[k("testpkg", "1.0.0")]
	if !ok {
		t.Fatal("no stored record")
	}
	if len(rec.Metadata) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Metadata, &m); err != nil {
		t.Fatalf("metadata not JSON: %v", err)
	}
	return m
}

func TestNpmProvenanceVerifyValidServes(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmValidAtt)
	a, _, _ := newProvenanceAdapter(t, srv, "") // mode deny (default)
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", code, body)
	}
}

func TestNpmProvenanceVerifyTamperedDenies(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmTamperedAtt)
	a, _, _ := newProvenanceAdapter(t, srv, "")
	s := newTestServer(t, a)
	code, _ := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != http.StatusForbidden {
		t.Fatalf("tampered provenance should be rejected with 403, got %d", code)
	}
}

func TestNpmProvenanceVerifyTamperedWarns(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmTamperedAtt)
	a, store, _ := newProvenanceAdapter(t, srv, "mode: warn")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", code, body)
	}
	m := npmProvenanceMeta(t, store)
	prov, _ := m["provenance"].(map[string]any)
	if prov["status"] != "invalid" {
		t.Fatalf("stored provenance metadata = %#v, want {\"status\":\"invalid\"}", m["provenance"])
	}
}

func TestNpmProvenanceVerifyAbsentNotRequiredServes(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmEmptyAtt)
	a, _, _ := newProvenanceAdapter(t, srv, "")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", code, body)
	}
}

func TestNpmProvenanceVerifyAbsentRequiredDenies(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmEmptyAtt)
	a, _, _ := newProvenanceAdapter(t, srv, "require_provenance: true")
	s := newTestServer(t, a)
	code, _ := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != http.StatusForbidden {
		t.Fatalf("missing provenance with require_provenance should be 403, got %d", code)
	}
}

// TestNpmProvenanceVerifyBindsArtifactDigest is the regression test for H3:
// the digest the verifier receives must be the sha256 of the bytes actually
// served (the real "TARBALL" tarball), proving the wiring from serveUntrusted
// through to the verifier is intact end to end.
func TestNpmProvenanceVerifyBindsArtifactDigest(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmValidAtt)
	a, _, cv := newProvenanceAdapter(t, srv, "")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", code, body)
	}
	want, _, err := hash.Sha256Hex(bytes.NewReader([]byte("TARBALL")))
	if err != nil {
		t.Fatal(err)
	}
	if got := cv.lastDigest(); got != want {
		t.Errorf("verifier received digest %q, want %q (the real served artifact's sha256)", got, want)
	}
}

func TestNpmProvenanceVerifyAbsentRequiredWarns(t *testing.T) {
	srv := npmProvenanceUpstream(t, npmEmptyAtt)
	a, store, _ := newProvenanceAdapter(t, srv, "mode: warn\nrequire_provenance: true")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", code, body)
	}
	m := npmProvenanceMeta(t, store)
	prov, _ := m["provenance"].(map[string]any)
	if prov["missing"] != true {
		t.Fatalf("stored provenance metadata = %#v, want {\"missing\":true}", m["provenance"])
	}
}
