package pypi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const indexJSON = `{"meta":{"api-version":"1.0"},"name":"testpkg","files":[
  {"filename":"testpkg-1.0.0-py3-none-any.whl","url":"http://up/testpkg-1.0.0-py3-none-any.whl","hashes":{"sha256":"abc"},"requires-python":">=3.8","upload-time":"2021-01-15T10:00:00.000000Z","size":123}
]}`

func newUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/simple/testpkg/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", acceptJSON)
		_, _ = io.WriteString(w, indexJSON)
	})
	mux.HandleFunc("/simple/missing/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux.HandleFunc("/file.whl", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("WHEEL-BYTES"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchIndex(t *testing.T) {
	srv := newUpstream(t)
	c, err := New(srv.URL+"/simple", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.FetchIndex(context.Background(), "TESTPKG") // NormalizeName -> testpkg
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if p.Name != "testpkg" || len(p.Files) != 1 {
		t.Fatalf("project = %+v", p)
	}
	f := p.Files[0]
	if f.Filename != "testpkg-1.0.0-py3-none-any.whl" || f.Hashes["sha256"] != "abc" || f.RequiresPython != ">=3.8" {
		t.Errorf("file = %+v", f)
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !f.UploadTime.Equal(want) {
		t.Errorf("upload-time = %v want %v", f.UploadTime, want)
	}
}

func TestFetchIndexRaw(t *testing.T) {
	srv := newUpstream(t)
	c, _ := New(srv.URL+"/simple", nil, nil)
	body, ct, err := c.FetchIndexRaw(context.Background(), "testpkg", acceptJSON)
	if err != nil {
		t.Fatal(err)
	}
	if ct != acceptJSON {
		t.Errorf("content-type = %q", ct)
	}
	if len(body) == 0 {
		t.Error("empty body")
	}
}

func TestFetchIndexNotFound(t *testing.T) {
	srv := newUpstream(t)
	c, _ := New(srv.URL+"/simple", nil, nil)
	_, err := c.FetchIndex(context.Background(), "missing")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetchFile(t *testing.T) {
	srv := newUpstream(t)
	c, _ := New(srv.URL+"/simple", nil, nil)
	rc, n, err := c.FetchFile(context.Background(), srv.URL+"/file.whl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "WHEEL-BYTES" || n != int64(len("WHEEL-BYTES")) {
		t.Errorf("body = %q n=%d", b, n)
	}
}

func TestNormalizeName(t *testing.T) {
	cases := map[string]string{"Foo.Bar": "foo-bar", "FOO__bar..baz": "foo-bar-baz", "already-good": "already-good"}
	for in, want := range cases {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNewRequiresUpstream(t *testing.T) {
	if _, err := New("", nil, nil); err == nil {
		t.Fatal("want error for empty upstream")
	}
}

// TestFetchFileRejectsInternalHost: an upstream-advertised file URL pointing
// at a cloud-metadata IP is rejected by the allowlist before any request is
// made.
func TestFetchFileRejectsInternalHost(t *testing.T) {
	srv := newUpstream(t)
	c, _ := New(srv.URL+"/simple", nil, nil)
	_, _, err := c.FetchFile(context.Background(), "http://169.254.169.254/x.whl")
	if err == nil {
		t.Fatal("want error for internal-host file URL")
	}
	if !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("err = %v, want allowlist rejection", err)
	}
}

// TestFetchFileRejectsRedirectToInternal: an upstream 302 to an internal host
// is rejected by the redirect allowlist check; the body is never read.
func TestFetchFileRejectsRedirectToInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/x.whl", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	c, _ := New(srv.URL+"/simple", nil, nil)
	rc, _, err := c.FetchFile(context.Background(), srv.URL+"/file.whl")
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
