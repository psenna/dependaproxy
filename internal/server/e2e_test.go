package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/registry/npm"
	"github.com/psenna/dependaproxy/internal/storage"
)

// makeTgz builds a minimal valid npm tarball (package/package.json +
// package/index.js) and returns its bytes and sha512 integrity.
func makeTgz(t *testing.T, name, version string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	pkgJSON := fmt.Sprintf(`{"name":%q,"version":%q,"main":"index.js"}`, name, version)
	writeTar(t, tw, "package/package.json", []byte(pkgJSON))
	writeTar(t, tw, "package/index.js", []byte("module.exports = 1;\n"))
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	h := sha512.Sum512(data)
	return data, "sha512-" + base64.StdEncoding.EncodeToString(h[:])
}

func writeTar(t *testing.T, tw *tar.Writer, name string, body []byte) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
}

// packumentJSON builds the full upstream packument JSON for one version.
func packumentJSON(name, version, upstream, integrity string, pub time.Time) []byte {
	tb := upstream + "/" + name + "/-/" + name + "-" + version + ".tgz"
	doc := map[string]any{
		"name": name,
		"versions": map[string]any{
			version: map[string]any{
				"version": version,
				"dist":    map[string]any{"tarball": tb, "integrity": integrity},
				"dependencies": map[string]any{
					"left-pad": "1.0.0",
				},
			},
		},
		"time":      map[string]string{version: pub.Format(time.RFC3339Nano)},
		"dist-tags": map[string]string{"latest": version},
	}
	b, _ := json.Marshal(doc)
	return b
}

type upstreamServer struct {
	*httptest.Server
	tarballHits *int32
}

func newUpstream(t *testing.T, packs map[string][]byte, tarballs map[string][]byte) *upstreamServer {
	t.Helper()
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if body, ok := packs[p]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		if body, ok := tarballs[p]; ok {
			atomic.AddInt32(&hits, 1)
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &upstreamServer{Server: srv, tarballHits: &hits}
}

func newProxy(t *testing.T, upstream string, st *memStorage, cacheDir string, minDays int) *httptest.Server {
	t.Helper()
	rc, err := npm.New(upstream, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Registry: "npm",
		Log:      config.Log{Level: "warn", Format: "json"},
		Validation: []config.Middleware{
			{Type: "min-publication-age", Params: yamlNode(fmt.Sprintf("min_days: %d", minDays))},
		},
		Retrieval: []config.Middleware{
			{Type: "local-disk-cache", Params: yamlNode("path: " + cacheDir)},
			{Type: "upstream-registry"},
		},
	}
	srv, err := New(context.Background(), cfg, st, rc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		httpSrv.Close()
		_ = srv.Close()
	})
	return httpSrv
}

// fetchTarballViaProxy does the npm-style flow: GET packument, read the
// rewritten dist.tarball URL, GET it.
func fetchTarballViaProxy(t *testing.T, proxy, pkg, version string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(proxy + "/" + pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	tb := doc["versions"].(map[string]any)[version].(map[string]any)["dist"].(map[string]any)["tarball"].(string)
	tresp, err := http.Get(tb) //nolint:gosec // G107: tb is the proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer tresp.Body.Close() //nolint:errcheck // test cleanup
	body, _ := io.ReadAll(tresp.Body)
	return tresp.StatusCode, body
}

func TestE2E_OldPackageInstallsAndCaches(t *testing.T) {
	oldTgz, integrity := makeTgz(t, "e2epkg", "1.0.0")
	packs := map[string][]byte{
		"/e2epkg": packumentJSON("e2epkg", "1.0.0", "", integrity, time.Now().AddDate(0, 0, -30)),
	}
	// The upstream packument tarball URL must point at the upstream server; fix below.
	up := newUpstream(t, packs, map[string][]byte{"/e2epkg/-/e2epkg-1.0.0.tgz": oldTgz})
	// Rewrite the packument's tarball URL to the real upstream base now that we know it.
	packs["/e2epkg"] = packumentJSON("e2epkg", "1.0.0", up.URL, integrity, time.Now().AddDate(0, 0, -30))

	st := newMemStorage()
	cacheDir := t.TempDir()
	proxy := newProxy(t, up.URL, st, cacheDir, 7)

	// First install: validate + store + cache.
	code, body := fetchTarballViaProxy(t, proxy.URL, "e2epkg", "1.0.0")
	if code != 200 || !bytes.Equal(body, oldTgz) {
		t.Fatalf("first install: code=%d body-match=%v", code, bytes.Equal(body, oldTgz))
	}
	if len(st.records) != 1 {
		t.Fatalf("expected stored record, got %d", len(st.records))
	}
	firstHits := atomic.LoadInt32(up.tarballHits)

	// Second install: served from cache, no upstream tarball hit.
	code, body = fetchTarballViaProxy(t, proxy.URL, "e2epkg", "1.0.0")
	if code != 200 || !bytes.Equal(body, oldTgz) {
		t.Fatalf("second install: code=%d", code)
	}
	if got := atomic.LoadInt32(up.tarballHits); got != firstHits {
		t.Errorf("second install hit upstream (hits=%d -> %d); cache should serve", firstHits, got)
	}
	// Cache file present.
	if _, err := os.Stat(filepath.Join(cacheDir, "npm", "e2epkg", "1.0.0.tgz")); err != nil {
		t.Errorf("cache file missing: %v", err)
	}
}

func TestE2E_FreshPackageRejected(t *testing.T) {
	freshTgz, integrity := makeTgz(t, "freshpkg", "1.0.0")
	packs := map[string][]byte{"/freshpkg": packumentJSON("freshpkg", "1.0.0", "", integrity, time.Now())}
	up := newUpstream(t, packs, map[string][]byte{"/freshpkg/-/freshpkg-1.0.0.tgz": freshTgz})
	packs["/freshpkg"] = packumentJSON("freshpkg", "1.0.0", up.URL, integrity, time.Now())

	st := newMemStorage()
	proxy := newProxy(t, up.URL, st, t.TempDir(), 7)

	code, _ := fetchTarballViaProxy(t, proxy.URL, "freshpkg", "1.0.0")
	if code != 403 {
		t.Fatalf("fresh package: code=%d want 403", code)
	}
	if len(st.records) != 0 {
		t.Errorf("rejected package must not be stored; records=%d", len(st.records))
	}
}

func TestE2E_CorruptDBHashRefusesServe(t *testing.T) {
	goodTgz, integrity := makeTgz(t, "e2epkg", "1.0.0")
	packs := map[string][]byte{"/e2epkg": packumentJSON("e2epkg", "1.0.0", "", integrity, time.Now().AddDate(0, 0, -30))}
	up := newUpstream(t, packs, map[string][]byte{"/e2epkg/-/e2epkg-1.0.0.tgz": goodTgz})
	packs["/e2epkg"] = packumentJSON("e2epkg", "1.0.0", up.URL, integrity, time.Now().AddDate(0, 0, -30))

	st := newMemStorage()
	// Pre-seed a trusted record with a WRONG hash (simulating a tampered DB).
	st.records[key("e2epkg", "1.0.0", "npm")] = storage.PackageRecord{
		Name: "e2epkg", Version: "1.0.0", Registry: "npm",
		ValidationHash: "deadbeef", ValidatedAt: time.Now().UTC(),
	}
	proxy := newProxy(t, up.URL, st, t.TempDir(), 7)

	code, _ := fetchTarballViaProxy(t, proxy.URL, "e2epkg", "1.0.0")
	if code != 502 {
		t.Fatalf("corrupt DB hash: code=%d want 502 (never serve a mismatch)", code)
	}
}
