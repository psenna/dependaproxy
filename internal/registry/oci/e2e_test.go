//go:build e2e

package oci

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
)

// TestFullStack_PullHelloWorld_LiveDockerHub drives the adapter exactly the
// way a real Docker client would: GET /v2/ ping, then a manifest pull, then
// a blob pull for a digest named in that manifest's own response headers --
// through the REAL Factory-built adapter (real config validation, real
// path-allowlist middleware, real go-containerregistry client), served over
// a real HTTP server. Run with:
//
//	go test -tags e2e ./internal/registry/oci/... -run FullStack -v
func TestFullStack_PullHelloWorld_LiveDockerHub(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name:     "docker",
		Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{
			Type: "path-allowlist", Params: mustParamsNode(t, "library/*"),
		}},
	}})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	srv := httptest.NewServer(http.StripPrefix("/v2", a.Handler()))
	defer srv.Close()
	client := srv.Client()

	// 1. Ping.
	resp, err := client.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ping status = %d, want 200", resp.StatusCode)
	}

	// 2. Manifest pull through the allowed upstream+path.
	resp, err = client.Get(srv.URL + "/v2/docker/library/hello-world/manifests/latest")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("manifest status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		t.Fatal("manifest response has no Docker-Content-Digest header")
	}

	// 3. Blob pull for that same digest (any manifest digest is also
	// separately fetchable as a blob per the registry-v2 spec).
	resp, err = client.Get(srv.URL + "/v2/docker/library/hello-world/blobs/" + digest)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("blob status = %d, want 200, body=%s", resp.StatusCode, body)
	}

	// 4. A path NOT covered by the "library/*" allowlist is denied, proving
	// the allowlist is actually wired into the live path, not just unit-tested
	// against a fake.
	resp, err = client.Get(srv.URL + "/v2/docker/someuser/hello-world/manifests/latest")
	if err != nil {
		t.Fatalf("denied pull: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied pull status = %d, want 403", resp.StatusCode)
	}
}
