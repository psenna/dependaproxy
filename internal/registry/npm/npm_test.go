package npm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/registry"
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

func newServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var tarballURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/@scope/pkg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, scopedPackument)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("TARBALL-BYTES"))
	})
	srv := httptest.NewServer(mux)
	tarballURL = srv.URL + "/tarball.tgz"
	t.Cleanup(srv.Close)
	// Patch the packument's tarball placeholder to the real server URL.
	return srv, &tarballURL
}

func TestFetchPackumentScoped(t *testing.T) {
	srv, tarballURL := newServer(t)
	c, err := New(srv.URL, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
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
		t.Fatal("missing version 1.0.0")
	}
	if v.Dist.Integrity != "sha512-abc" {
		t.Errorf("integrity = %q", v.Dist.Integrity)
	}
	if v.Dist.Tarball != "TARBALL_URL" {
		t.Errorf("tarball = %q", v.Dist.Tarball)
	}
	pub, ok := p.Time["1.0.0"]
	if !ok {
		t.Fatal("missing time[1.0.0]")
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !pub.Equal(want) {
		t.Errorf("time = %v want %v", pub, want)
	}
	// dist-tags present
	if p.DistTags["latest"] != "1.0.0" {
		t.Errorf("dist-tags latest = %q", p.DistTags["latest"])
	}
	_ = tarballURL // used in tarball test below
}

func TestFetchPackumentNotFound(t *testing.T) {
	srv, _ := newServer(t)
	c, _ := New(srv.URL, nil)
	_, err := c.FetchPackument(context.Background(), "missing")
	if err != registry.ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetchPackumentRaw(t *testing.T) {
	srv, _ := newServer(t)
	c, _ := New(srv.URL, nil)
	raw, err := c.FetchPackumentRaw(context.Background(), "@scope/pkg")
	if err != nil {
		t.Fatalf("fetch raw: %v", err)
	}
	if !strings.Contains(string(raw), `"@scope/pkg"`) {
		t.Errorf("raw packument missing name: %q", raw)
	}
}

func TestFetchTarballStreamsBytes(t *testing.T) {
	srv, tarballURL := newServer(t)
	c, _ := New(srv.URL, nil)
	rc, n, err := c.FetchTarball(context.Background(), *tarballURL)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer func() { _ = rc.Close() }()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "TARBALL-BYTES" {
		t.Errorf("body = %q", body)
	}
	if n != int64(len("TARBALL-BYTES")) {
		t.Errorf("content-length = %d want %d", n, len("TARBALL-BYTES"))
	}
}

func TestFetchTarballNotFound(t *testing.T) {
	srv, _ := newServer(t)
	c, _ := New(srv.URL, nil)
	_, _, err := c.FetchTarball(context.Background(), srv.URL+"/missing")
	if err != registry.ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestNewRequiresUpstream(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("want error for empty upstream")
	}
}
