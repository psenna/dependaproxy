package goproxy

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestAdapter builds a goproxyAdapter wired to a real client for upstream.
func newTestAdapter(t *testing.T, prefix, upstream string) *goproxyAdapter {
	t.Helper()
	client, err := New(upstream, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &goproxyAdapter{
		prefix: prefix,
		client: client,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

func newTestServer(t *testing.T, a *goproxyAdapter) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.StripPrefix(a.prefix, a.Handler()))
	t.Cleanup(srv.Close)
	return srv
}

// get proxies a GET through the test server and returns status, headers, body.
func get(t *testing.T, url string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, body
}

func TestGoproxyList(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/list")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if string(body) != testListBody {
		t.Errorf("body = %q want %q", body, testListBody)
	}
}

func TestGoproxyInfo(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".info")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.Version != testVersion {
		t.Errorf("version = %q", info.Version)
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !info.Time.Equal(want) {
		t.Errorf("time = %v want %v", info.Time, want)
	}
}

func TestGoproxyMod(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".mod")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if string(body) != testModBody {
		t.Errorf("body = %q want %q", body, testModBody)
	}
}

func TestGoproxyZip(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("content-type = %q", ct)
	}
	if cl := hdr.Get("Content-Length"); cl != "9" {
		t.Errorf("content-length = %q", cl)
	}
	if string(body) != testZipBody {
		t.Errorf("body = %q", body)
	}
}

func TestGoproxyLatest(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@latest")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if info.Version != "v1.1.0" {
		t.Errorf("version = %q", info.Version)
	}
}

func TestGoproxyUpstreamNotFound(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, _, _ := get(t, srv.URL+"/goproxy/example.com/missing/@v/list")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d want 404", code)
	}
}

func TestGoproxyUpstream5xx(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, _, _ := get(t, srv.URL+"/goproxy/example.com/bad/@v/list")
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d want 502", code)
	}
}

func TestGoproxyInvalidEscapedPath(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	// Uppercase without a "!" escape is not a valid escaped module path.
	code, _, body := get(t, srv.URL+"/goproxy/github.com/Azure/azure-sdk-for-go/@v/list")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d want 400", code)
	}
	if !strings.Contains(string(body), "invalid module path") {
		t.Errorf("body = %q", body)
	}
}

func TestGoproxyProjectPrefixStripped(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/p/myproj/"+testModuleEscaped+"/@v/list")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if string(body) != testListBody {
		t.Errorf("body = %q want %q", body, testListBody)
	}
}

func TestGoproxyMethodNotAllowed(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	resp, err := http.Post(srv.URL+"/goproxy/"+testModuleEscaped+"/@v/list", "text/plain", nil) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d want 405", resp.StatusCode)
	}
}

func TestGoproxyUnknownRoute(t *testing.T) {
	up, _ := newUpstream(t)
	a := newTestAdapter(t, "/goproxy", up.URL)
	srv := newTestServer(t, a)

	for _, p := range []string{
		"/goproxy/foo",
		"/goproxy/" + testModuleEscaped + "/@v/v1.0.0.unknown",
		"/goproxy/" + testModuleEscaped + "/@v/",
		"/goproxy/@v/list",
	} {
		code, _, _ := get(t, srv.URL+p)
		if code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d want 404", p, code)
		}
	}
}
