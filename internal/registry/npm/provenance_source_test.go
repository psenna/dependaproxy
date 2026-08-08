package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

const bundleJSON = `{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","payload":"VALID","signatures":[{"sig":"x"}]}`

// attestationDoc wraps a sigstore bundle in the shape the npm attestations
// endpoint serves: {"attestations":[{"predicateType":..., "bundle":{...}}]}.
const attestationDoc = `{"attestations":[{"predicateType":"https://slsa.dev/provenance/v0.2","bundle":` + bundleJSON + `}]}`

// packumentJSON builds a raw packument whose version 1.0.0 carries
// dist.attestations.url = attURL and dist.tarball = tarURL.
func packumentJSON(attURL, tarURL string) []byte {
	p := &Packument{
		Name: "testpkg",
		Versions: map[string]Version{
			"1.0.0": {Version: "1.0.0", Dist: Dist{
				Tarball:      tarURL,
				Integrity:    "sha512-x",
				Attestations: &Attestations{URL: attURL},
			}},
		},
	}
	raw, _ := json.Marshal(p)
	return raw
}

func newNpmClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func npmCtx(idx any) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{
		Ctx:      context.Background(),
		Registry: "npm",
		PkgName:  "testpkg",
		Version:  "1.0.0",
		Index:    idx,
	}
}

// upstream serves /testpkg (packument), /attestations (the attestation doc) and
// /t.tgz (tarball). missingAtt disables the dist.attestations field.
func upstream(t *testing.T, missingAtt bool) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/testpkg":
			w.Header().Set("Content-Type", "application/json")
			if missingAtt {
				p := &Packument{Name: "testpkg", Versions: map[string]Version{
					"1.0.0": {Version: "1.0.0", Dist: Dist{Tarball: srv.URL + "/t.tgz", Integrity: "sha512-x"}},
				}}
				raw, _ := json.Marshal(p)
				_, _ = w.Write(raw)
				return
			}
			_, _ = w.Write(packumentJSON(srv.URL+"/attestations", srv.URL+"/t.tgz"))
		case "/attestations":
			_, _ = w.Write([]byte(attestationDoc))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestNpmProvenanceSourceIndexPath uses the ctx.Index-populated path: the
// packument on ctx.Index carries dist.attestations.url, so the source must
// fetch the attestation document (FetchBytes) WITHOUT a second packument fetch.
func TestNpmProvenanceSourceIndexPath(t *testing.T) {
	srv := upstream(t, false)
	c := newNpmClient(t, srv)

	pack := &Packument{Name: "testpkg", Versions: map[string]Version{
		"1.0.0": {Version: "1.0.0", Dist: Dist{Attestations: &Attestations{URL: srv.URL + "/attestations"}}},
	}}
	src := NewProvenanceSource(c)
	bundles, err := src.Attestations(npmCtx(pack))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("bundles = %d, want 1", len(bundles))
	}
	var got map[string]any
	if err := json.Unmarshal(bundles[0], &got); err != nil {
		t.Fatalf("bundle should be JSON: %v", err)
	}
	if got["payload"] != "VALID" {
		t.Errorf("bundle payload = %v, want VALID", got["payload"])
	}
}

// TestNpmProvenanceSourceNilIndexPath falls back to a raw packument fetch when
// ctx.Index is nil (cache short-circuit), then fetches the attestation doc from
// the packument-advertised URL.
func TestNpmProvenanceSourceNilIndexPath(t *testing.T) {
	srv := upstream(t, false)
	c := newNpmClient(t, srv)

	src := NewProvenanceSource(c)
	bundles, err := src.Attestations(npmCtx(nil))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("bundles = %d, want 1", len(bundles))
	}
}

// TestNpmProvenanceSourceNoAttestations: a packument without attestations
// yields (nil, nil) on both the index and nil-index paths.
func TestNpmProvenanceSourceNoAttestations(t *testing.T) {
	srv := upstream(t, true)
	c := newNpmClient(t, srv)
	src := NewProvenanceSource(c)

	pack := &Packument{Name: "testpkg", Versions: map[string]Version{
		"1.0.0": {Version: "1.0.0", Dist: Dist{}},
	}}
	bundles, err := src.Attestations(npmCtx(pack))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("bundles = %d, want 0", len(bundles))
	}

	bundles, err = src.Attestations(npmCtx(nil))
	if err != nil {
		t.Fatalf("Attestations (nil index): %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("bundles = %d, want 0", len(bundles))
	}
}

// TestNpmProvenanceSourceBundleNotFound: a 404 on the attestation URL is
// treated as "no attestations published" -> (nil, nil).
func TestNpmProvenanceSourceBundleNotFound(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/testpkg":
			_, _ = w.Write(packumentJSON(srv.URL+"/attestations", srv.URL+"/t.tgz"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	src := NewProvenanceSource(c)
	bundles, err := src.Attestations(npmCtx(nil))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("bundles = %d, want 0", len(bundles))
	}
}
