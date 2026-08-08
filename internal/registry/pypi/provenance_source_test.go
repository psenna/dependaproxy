package pypi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

const pep740Bundle = `{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","payload":"VALID","signatures":[{"sig":"x"}]}`

// pep740Doc mimics the PEP 740 attestations document shape served by PyPI:
//
//	{"version":1,"attestations":{"<file-digest>":{"attestation_bundles":[
//	  {"attestation":{<sigstore bundle>}}]}}}
const pep740Doc = `{"version":1,"attestations":{"sha256:deadbeef":{"attestation_bundles":[{"attestation":` + pep740Bundle + `}]}}}`

func pypiCtx(name string) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{
		Ctx:      context.Background(),
		Registry: "pypi",
		PkgName:  name,
		Version:  "1.0.0",
	}
}

func newPypiClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPypiProvenanceSourceExtractsBundles serves a PEP 740 document and
// asserts the sigstore bundle is extracted.
func TestPypiProvenanceSourceExtractsBundles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/testpkg/1.0.0/attestations/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(pep740Doc))
	}))
	t.Cleanup(srv.Close)

	src := NewProvenanceSource(newPypiClient(t, srv))
	bundles, err := src.Attestations(pypiCtx("testpkg"))
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

// TestPypiProvenanceSourceNameNormalization passes a non-normalized project
// name and asserts the request path uses the PEP 503 normalization
// ("Test_Pkg.1" -> "test-pkg-1").
func TestPypiProvenanceSourceNameNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test-pkg-1/1.0.0/attestations/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(pep740Doc))
	}))
	t.Cleanup(srv.Close)

	src := NewProvenanceSource(newPypiClient(t, srv))
	bundles, err := src.Attestations(pypiCtx("Test_Pkg.1"))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("bundles = %d, want 1", len(bundles))
	}
}

// TestPypiProvenanceSourceNotFound: a 404 on the attestations endpoint means
// no attestations were published -> (nil, nil).
func TestPypiProvenanceSourceNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	src := NewProvenanceSource(newPypiClient(t, srv))
	bundles, err := src.Attestations(pypiCtx("testpkg"))
	if err != nil {
		t.Fatalf("Attestations: %v", err)
	}
	if len(bundles) != 0 {
		t.Fatalf("bundles = %d, want 0", len(bundles))
	}
}
