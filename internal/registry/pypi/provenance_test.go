package pypi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/provenance"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// pypiContentVerifier is the adapter-test fake: it passes bundles whose payload
// contains "VALID" and rejects everything else (tampered).
type pypiContentVerifier struct{}

func (pypiContentVerifier) Verify(_ context.Context, b []byte) (bool, error) {
	return bytes.Contains(b, []byte("VALID")), nil
}

const (
	pypiValidAtt    = `{"version":1,"attestations":{"sha256:deadbeef":{"attestation_bundles":[{"attestation":{"mediaType":"m","payload":"VALID"}}]}}}`
	pypiTamperedAtt = `{"version":1,"attestations":{"sha256:deadbeef":{"attestation_bundles":[{"attestation":{"mediaType":"m","payload":"TAMPERED"}}]}}}`
	pypiEmptyAtt    = `{"version":1,"attestations":{}}`
)

const pypiWheel = "testpkg-1.0.0-py3-none-any.whl"

// pypiProvenanceUpstream serves the PEP 691 index, the wheel, and the PEP 740
// attestations document.
func pypiProvenanceUpstream(t *testing.T, attBody string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/testpkg/":
			raw := []byte(`{"meta":{"api-version":"1.0"},"name":"testpkg","files":[{"filename":"` + pypiWheel + `","url":"` + srv.URL + `/files/` + pypiWheel + `","requires-python":">=3.7"}]}`)
			w.Header().Set("Content-Type", acceptJSON)
			_, _ = w.Write(raw)
		case "/testpkg/1.0.0/attestations/":
			_, _ = w.Write([]byte(attBody))
		case "/files/" + pypiWheel:
			_, _ = w.Write([]byte("WHEEL"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newProvenanceAdapter wires the pypi pipeline with provenance-verify whose
// verifier is the contentVerifier fake (no real sigstore / no network).
func newProvenanceAdapter(t *testing.T, srv *httptest.Server, params string) (*pypiAdapter, *memStore) {
	t.Helper()
	dir := t.TempDir()
	store := newMemStore()
	client, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("provenance-verify", func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr provenance.Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("provenance-verify: decode params: %w", err)
			}
		}
		return provenance.New(pr, NewProvenanceSource(client), pypiContentVerifier{}), nil
	})
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "provenance-verify", Params: pyYamlNode(params)},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: pyYamlNode("path: " + dir)},
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
	resolver := project.NewResolver("pypi", reg, fakeProjectStore{}, global)
	a := &pypiAdapter{
		prefix:   "/pypi",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
	return a, store
}

func pypiProvenanceMeta(t *testing.T, store *memStore) map[string]any {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	rec, ok := store.recs[pkey("testpkg", "1.0.0", pypiWheel)]
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

func TestPypiProvenanceVerifyValidServes(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiValidAtt)
	a, _ := newProvenanceAdapter(t, srv, "") // mode deny (default)
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("code=%d body=%q want 200/WHEEL", code, body)
	}
}

func TestPypiProvenanceVerifyTamperedDenies(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiTamperedAtt)
	a, _ := newProvenanceAdapter(t, srv, "")
	s := newTestServer(t, a)
	code, _ := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != http.StatusForbidden {
		t.Fatalf("tampered provenance should be rejected with 403, got %d", code)
	}
}

func TestPypiProvenanceVerifyTamperedWarns(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiTamperedAtt)
	a, store := newProvenanceAdapter(t, srv, "mode: warn")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("code=%d body=%q want 200/WHEEL", code, body)
	}
	m := pypiProvenanceMeta(t, store)
	prov, _ := m["provenance"].(map[string]any)
	if prov["status"] != "invalid" {
		t.Fatalf("stored provenance metadata = %#v, want {\"status\":\"invalid\"}", m["provenance"])
	}
}

func TestPypiProvenanceVerifyAbsentNotRequiredServes(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiEmptyAtt)
	a, _ := newProvenanceAdapter(t, srv, "")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("code=%d body=%q want 200/WHEEL", code, body)
	}
}

func TestPypiProvenanceVerifyAbsentRequiredDenies(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiEmptyAtt)
	a, _ := newProvenanceAdapter(t, srv, "require_provenance: true")
	s := newTestServer(t, a)
	code, _ := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != http.StatusForbidden {
		t.Fatalf("missing provenance with require_provenance should be 403, got %d", code)
	}
}

func TestPypiProvenanceVerifyAbsentRequiredWarns(t *testing.T) {
	srv := pypiProvenanceUpstream(t, pypiEmptyAtt)
	a, store := newProvenanceAdapter(t, srv, "mode: warn\nrequire_provenance: true")
	s := newTestServer(t, a)
	code, body := fetchViaProxy(t, s.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("code=%d body=%q want 200/WHEEL", code, body)
	}
	m := pypiProvenanceMeta(t, store)
	prov, _ := m["provenance"].(map[string]any)
	if prov["missing"] != true {
		t.Fatalf("stored provenance metadata = %#v, want {\"missing\":true}", m["provenance"])
	}
}
