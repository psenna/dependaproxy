package oci

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"gopkg.in/yaml.v3"
)

// fakeClient is a manifestBlobGetter test double -- the manifest/blob route
// tests reuse this too.
type fakeClient struct {
	manifest    *ManifestResult
	manifestErr error
	blobData    []byte
	blobType    string
	blobErr     error
}

func (f *fakeClient) GetManifest(context.Context, string, string) (*ManifestResult, error) {
	return f.manifest, f.manifestErr
}

func (f *fakeClient) GetBlob(context.Context, string, string) ([]byte, string, error) {
	return f.blobData, f.blobType, f.blobErr
}

var errNotFound = errors.New("fake: not found")

type errUnexpectedCall struct{}

func (errUnexpectedCall) Error() string { return "fake client was called when it should not have been" }

func adapterDeps() adapter.Deps {
	return adapter.Deps{Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return time.Time{} }}
}

func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var envelope struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("response body is not the error envelope: %v (body: %s)", err, body)
	}
	if len(envelope.Errors) != 1 || envelope.Errors[0].Code != want {
		t.Fatalf("errors = %+v, want exactly one entry with code %q", envelope.Errors, want)
	}
}

func mustParamsNode(t *testing.T, pattern string) (n yaml.Node) {
	t.Helper()
	if err := n.Encode(struct {
		Patterns []string `yaml:"patterns"`
	}{Patterns: []string{pattern}}); err != nil {
		t.Fatal(err)
	}
	return n
}

func testAdapter(t *testing.T) *ociAdapter {
	t.Helper()
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{
		{Name: "docker", Upstream: "https://registry-1.docker.io"},
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	// Swap in a fake client so routing tests never touch the network.
	a.upstreams["docker"].client = &fakeClient{manifestErr: errNotFound}
	return a
}

func TestAdapter_Prefix(t *testing.T) {
	a := testAdapter(t)
	if got := a.Prefix(); got != "/v2" {
		t.Errorf("Prefix() = %q, want /v2", got)
	}
}

func TestAdapter_PingRoute(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
		t.Errorf("Docker-Distribution-API-Version = %q, want registry/2.0", got)
	}
	if got := rec.Body.String(); got != "{}" {
		t.Errorf("body = %q, want {}", got)
	}
}

func TestAdapter_PingRoute_DoesNotTouchAnyUpstream(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifestErr: errUnexpectedCall{}}
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (ping must never call an upstream client)", rec.Code)
	}
}

func TestAdapter_UnknownUpstreamName(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/nope/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeNameUnknown)
}

func TestAdapter_InvalidateProjectCache_NoOp(t *testing.T) {
	a := testAdapter(t)
	a.InvalidateProjectCache("anything") // must not panic
}

func TestFactory_RejectsWrongPrefix(t *testing.T) {
	_, err := Factory(context.Background(), config.RegistryConfig{
		Type: "oci", Prefix: "/oci",
		Upstreams: []config.OCIUpstreamConfig{{Name: "docker", Upstream: "https://registry-1.docker.io"}},
	}, adapterDeps())
	if err == nil {
		t.Fatal("Factory() = nil error, want an error: prefix must be /v2")
	}
}

func TestFactory_BuildsPathAllowlist(t *testing.T) {
	a, err := Factory(context.Background(), config.RegistryConfig{
		Type: "oci", Prefix: "/v2",
		Upstreams: []config.OCIUpstreamConfig{{
			Name: "docker", Upstream: "https://registry-1.docker.io",
			Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
		}},
	}, adapterDeps())
	if err != nil {
		t.Fatalf("Factory() error = %v", err)
	}
	if a.Prefix() != "/v2" {
		t.Errorf("Prefix() = %q, want /v2", a.Prefix())
	}
}

func TestAdapter_ManifestRoute_Success(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifest: &ManifestResult{
		Bytes: []byte(`{"schemaVersion":2}`), MediaType: "application/vnd.docker.distribution.manifest.v2+json", Digest: "sha256:deadbeef",
	}}
	req := httptest.NewRequest("GET", "/docker/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "sha256:deadbeef" {
		t.Errorf("Docker-Content-Digest = %q, want sha256:deadbeef", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.docker.distribution.manifest.v2+json" {
		t.Errorf("Content-Type = %q, want the manifest media type", got)
	}
	if rec.Body.String() != `{"schemaVersion":2}` {
		t.Errorf("body = %q, want the manifest bytes verbatim", rec.Body.String())
	}
}

func TestAdapter_ManifestRoute_DeniedByAllowlist(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name: "docker", Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.upstreams["docker"].client = &fakeClient{manifestErr: errUnexpectedCall{}} // must never be called

	req := httptest.NewRequest("GET", "/docker/someuser/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeDenied)
}

func TestAdapter_ManifestRoute_UpstreamNotFound(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifestErr: errNotFound}
	req := httptest.NewRequest("GET", "/docker/library/nope/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeManifestUnknown)
}

func TestAdapter_ManifestRoute_MalformedName(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/docker/manifests-with-no-name", nil) // no "/manifests/<ref>" suffix
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAdapter_BlobRoute_Success(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{blobData: []byte("blob-bytes"), blobType: "application/octet-stream"}
	req := httptest.NewRequest("GET", "/docker/library/nginx/blobs/sha256:deadbeef", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "sha256:deadbeef" {
		t.Errorf("Docker-Content-Digest = %q, want the requested digest", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if rec.Body.String() != "blob-bytes" {
		t.Errorf("body = %q, want blob-bytes", rec.Body.String())
	}
}

func TestAdapter_BlobRoute_DeniedByAllowlist(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name: "docker", Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.upstreams["docker"].client = &fakeClient{blobErr: errUnexpectedCall{}}

	req := httptest.NewRequest("GET", "/docker/someuser/nginx/blobs/sha256:deadbeef", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeDenied)
}

func TestAdapter_BlobRoute_UpstreamNotFound(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{blobErr: errNotFound}
	req := httptest.NewRequest("GET", "/docker/library/nginx/blobs/sha256:missing", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeBlobUnknown)
}
