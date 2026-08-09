package goproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testModule        = "github.com/Azure/azure-sdk-for-go"
	testModuleEscaped = "github.com/!azure/azure-sdk-for-go"
	testVersion       = "v1.0.0"
	testZipBody       = "ZIP-BYTES"
	testListBody      = "v1.0.0\nv1.1.0\n"
	testModBody       = "module " + testModule + "\n"
	testInfoBody      = `{"Version":"v1.0.0","Time":"2021-01-15T10:00:00Z"}`
	testLatestBody    = `{"Version":"v1.1.0","Time":"2021-02-01T00:00:00Z"}`
)

// newUpstream serves the GOPROXY endpoints for the escaped Azure module path,
// plus 404/5xx fixtures, and records the last request path it saw.
func newUpstream(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		switch r.URL.Path {
		case "/" + testModuleEscaped + "/@v/list":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, testListBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, testInfoBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".mod":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, testModBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, testZipBody)
		case "/" + testModuleEscaped + "/@latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, testLatestBody)
		case "/example.com/missing/@v/list", "/example.com/missing/@latest":
			w.WriteHeader(http.StatusNotFound)
		case "/example.com/bad/@v/list":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &lastPath
}

func TestFetchList(t *testing.T) {
	srv, _ := newUpstream(t)
	c, err := New(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := c.FetchList(context.Background(), testModule)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(versions) != 2 || versions[0] != "v1.0.0" || versions[1] != "v1.1.0" {
		t.Errorf("versions = %v", versions)
	}
}

func TestFetchListTrailingNewlines(t *testing.T) {
	// A list with multiple trailing newlines must not yield a spurious empty
	// version (issue #125).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "v1.0.0\nv1.1.0\n\n")
	}))
	defer srv.Close()
	c, err := New(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := c.FetchList(context.Background(), testModule)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(versions) != 2 || versions[0] != "v1.0.0" || versions[1] != "v1.1.0" {
		t.Errorf("versions = %v, want [v1.0.0 v1.1.0] (no empty entry)", versions)
	}
}

func TestFetchInfo(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	info, err := c.FetchInfo(context.Background(), testModule, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != testVersion {
		t.Errorf("version = %q", info.Version)
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !info.Time.Equal(want) {
		t.Errorf("time = %v want %v", info.Time, want)
	}
}

func TestFetchMod(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	b, err := c.FetchMod(context.Background(), testModule, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != testModBody {
		t.Errorf("mod = %q", b)
	}
}

func TestFetchZip(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	rc, n, err := c.FetchZip(context.Background(), testModule, testVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != testZipBody {
		t.Errorf("body = %q", b)
	}
	if n != int64(len(testZipBody)) {
		t.Errorf("content-length = %d", n)
	}
}

func TestFetchLatest(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	info, err := c.FetchLatest(context.Background(), testModule)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != "v1.1.0" {
		t.Errorf("version = %q", info.Version)
	}
}

func TestFetchListNotFound(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	_, err := c.FetchList(context.Background(), "example.com/missing")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetchUpstream5xx(t *testing.T) {
	srv, _ := newUpstream(t)
	c, _ := New(srv.URL, nil)
	_, err := c.FetchList(context.Background(), "example.com/bad")
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v want non-ErrNotFound error", err)
	}
}

func TestNewRequiresUpstream(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Fatal("want error for empty upstream")
	}
	if _, err := New("   ", nil); err == nil {
		t.Fatal("want error for whitespace upstream")
	}
}

func TestEscapeUsedInURL(t *testing.T) {
	srv, lastPath := newUpstream(t)
	c, _ := New(srv.URL, nil)
	if _, err := c.FetchList(context.Background(), testModule); err != nil {
		t.Fatal(err)
	}
	if *lastPath != "/"+testModuleEscaped+"/@v/list" {
		t.Errorf("upstream path = %q, want escaped %q", *lastPath, "/"+testModuleEscaped+"/@v/list")
	}
}
