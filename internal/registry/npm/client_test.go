package npm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const scopedPackument = `{
  "name": "@scope/pkg",
  "versions": {
    "1.0.0": {
      "version": "1.0.0",
      "dist": { "tarball": "TARBALL_URL", "integrity": "sha512-abc" },
      "dependencies": { "left-pad": "1.0.0" }
    }
  },
  "time": {
    "created": "2021-01-01T00:00:00.000Z",
    "modified": "2021-06-01T00:00:00.000Z",
    "1.0.0": "2021-01-15T10:00:00.000Z"
  },
  "dist-tags": { "latest": "1.0.0" }
}`

func newUpstream(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var tarballURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/@scope/pkg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, scopedPackument)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("TARBALL-BYTES"))
	})
	srv := httptest.NewServer(mux)
	tarballURL = srv.URL + "/tarball.tgz"
	t.Cleanup(srv.Close)
	return srv, &tarballURL
}

func TestFetchPackumentScoped(t *testing.T) {
	srv, _ := newUpstream(t)
	c, err := New(srv.URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.FetchPackument(context.Background(), "@scope/pkg")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if p.Name != "@scope/pkg" {
		t.Errorf("name = %q", p.Name)
	}
	v, ok := p.Versions["1.0.0"]
	if !ok {
		t.Fatal("missing version")
	}
	if v.Dist.Integrity != "sha512-abc" || v.Dist.Tarball != "TARBALL_URL" {
		t.Errorf("dist = %+v", v.Dist)
	}
	pub, ok := p.Time["1.0.0"]
	if !ok {
		t.Fatal("missing time")
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !pub.Equal(want) {
		t.Errorf("time = %v want %v", pub, want)
	}
}

func TestFetchPackumentRaw(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil, nil)
	raw, err := c.FetchPackumentRaw(context.Background(), "@scope/pkg")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"@scope/pkg"`) {
		t.Errorf("raw missing name: %q", raw)
	}
}

func TestFetchPackumentNotFound(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil, nil)
	_, err := c.FetchPackument(context.Background(), "missing")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetchTarballStreamsBytes(t *testing.T) {
	srv, tarballURL := newUpstream(t)
	c, _ := New(srv.URL, nil, nil)
	rc, n, err := c.FetchTarball(context.Background(), *tarballURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "TARBALL-BYTES" {
		t.Errorf("body = %q", b)
	}
	if n != int64(len("TARBALL-BYTES")) {
		t.Errorf("content-length = %d", n)
	}
}

func TestNewRequiresUpstream(t *testing.T) {
	if _, err := New("", nil, nil); err == nil {
		t.Fatal("want error for empty upstream")
	}
}

// TestFetchTarballRejectsInternalHost: an upstream-advertised tarball URL
// pointing at a cloud-metadata IP is rejected by the allowlist before any
// request is made.
func TestFetchTarballRejectsInternalHost(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil, nil)
	_, _, err := c.FetchTarball(context.Background(), "http://169.254.169.254/x.tgz")
	if err == nil {
		t.Fatal("want error for internal-host tarball URL")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("err = %v, want allowlist rejection", err)
	}
}

// TestFetchBytesRejectsInternalHost: a provenance dist.attestations.url
// pointing at an internal host is rejected by the allowlist.
func TestFetchBytesRejectsInternalHost(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil, nil)
	_, err := c.FetchBytes(context.Background(), "http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("want error for internal-host provenance URL")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("err = %v, want allowlist rejection", err)
	}
}

// TestFetchTarballRejectsRedirectToInternal: an upstream 302 to an internal
// host is rejected by the redirect allowlist check; the body is never read.
func TestFetchTarballRejectsRedirectToInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/x.tgz", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	c, _ := New(srv.URL, nil, nil)
	rc, _, err := c.FetchTarball(context.Background(), srv.URL+"/tarball.tgz")
	if err == nil {
		if rc != nil {
			_ = rc.Close()
		}
		t.Fatal("want error following redirect to internal host")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("err = %v, want allowlist rejection", err)
	}
}

// TestFetchTarballAllowsExtraHost: a host in the operator-configured extra
// allowlist (here 127.0.0.1, not the base upstream host) is fetched normally.
func TestFetchTarballAllowsExtraHost(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New("http://registry.example.com", []string{"127.0.0.1"}, nil)
	rc, n, err := c.FetchTarball(context.Background(), srv.URL+"/tarball.tgz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "TARBALL-BYTES" || n != int64(len("TARBALL-BYTES")) {
		t.Errorf("body = %q n=%d", b, n)
	}
}
