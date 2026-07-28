package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/registry"
	"github.com/psenna/dependaproxy/internal/storage"
	"gopkg.in/yaml.v3"
)

// --- fakes ---

type memStorage struct {
	mu      sync.Mutex
	records map[string]storage.PackageRecord
}

func newMemStorage() *memStorage { return &memStorage{records: map[string]storage.PackageRecord{}} }

func key(name, ver, reg string) string { return name + "|" + ver + "|" + reg }

func (m *memStorage) Get(_ context.Context, name, ver, reg string) (storage.PackageRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[key(name, ver, reg)]
	if !ok {
		return storage.PackageRecord{}, storage.ErrNotFound
	}
	return r, nil
}

func (m *memStorage) Put(_ context.Context, r storage.PackageRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[key(r.Name, r.Version, r.Registry)] = r
	return nil
}

func (m *memStorage) Close() error { return nil }

type fakeReg struct {
	packument *registry.Packument
	raw       []byte
	tarball   []byte
	packCalls int32
	rawCalls  int32
	tarCalls  int32
}

func (f *fakeReg) FetchPackument(_ context.Context, _ string) (*registry.Packument, error) {
	atomic.AddInt32(&f.packCalls, 1)
	return f.packument, nil
}

func (f *fakeReg) FetchPackumentRaw(_ context.Context, _ string) ([]byte, error) {
	atomic.AddInt32(&f.rawCalls, 1)
	return f.raw, nil
}

func (f *fakeReg) FetchTarball(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	atomic.AddInt32(&f.tarCalls, 1)
	return io.NopCloser(bytes.NewReader(f.tarball)), int64(len(f.tarball)), nil
}

// --- helpers ---

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

func testConfig(cacheDir, token string, minDays int) *config.Config {
	return &config.Config{
		Auth:     config.Auth{Token: token},
		Registry: "npm",
		Upstream: "http://fake",
		Log:      config.Log{Level: "info", Format: "json"},
		Validation: []config.Middleware{
			{Type: "min-publication-age", Params: yamlNode(fmt.Sprintf("min_days: %d", minDays))},
		},
		Retrieval: []config.Middleware{
			{Type: "local-disk-cache", Params: yamlNode(fmt.Sprintf("path: %s", cacheDir))},
			{Type: "upstream-registry"},
		},
	}
}

func newTestServer(t *testing.T, st *memStorage, reg registry.RegistryClient, cfg *config.Config) *Server {
	t.Helper()
	srv, err := New(context.Background(), cfg, st, reg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func doRequest(t *testing.T, h http.Handler, method, target string, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// buildPackument returns a trimmed packument + full raw JSON for "testpkg@1.0.0".
func buildPackument(pub time.Time, tarball []byte) (*registry.Packument, []byte) {
	p := &registry.Packument{
		Name: "testpkg",
		Versions: map[string]registry.Version{
			"1.0.0": {Version: "1.0.0", Dist: registry.Dist{Tarball: "http://fake/testpkg/-/testpkg-1.0.0.tgz", Integrity: "sha512-abc"}},
		},
		Time:     map[string]time.Time{"1.0.0": pub},
		DistTags: map[string]string{"latest": "1.0.0"},
	}
	raw := []byte(`{"name":"testpkg","versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"http://fake/testpkg/-/testpkg-1.0.0.tgz","integrity":"sha512-abc"},"dependencies":{"left-pad":"1.0.0"}}},"time":{"1.0.0":"` + pub.Format(time.RFC3339Nano) + `"},"dist-tags":{"latest":"1.0.0"}}`)
	return p, raw
}

// --- tests ---

func TestUntrustedValidatesStoresServes(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	pack, raw := buildPackument(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	reg := &fakeReg{packument: pack, raw: raw, tarball: []byte("TARBALL")}
	srv := newTestServer(t, st, reg, testConfig(dir, "", 0))
	h := srv.Handler()

	rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "")
	if rr.Code != 200 || rr.Body.String() != "TARBALL" {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
	if len(st.records) != 1 {
		t.Fatalf("expected 1 stored record, got %d", len(st.records))
	}
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("TARBALL")))
	if st.records[key("testpkg", "1.0.0", "npm")].ValidationHash != wantHash {
		t.Errorf("stored hash mismatch")
	}
}

func TestTrustedServedFromCache(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	pack, raw := buildPackument(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	reg := &fakeReg{packument: pack, raw: raw, tarball: []byte("TARBALL")}
	srv := newTestServer(t, st, reg, testConfig(dir, "", 0))
	h := srv.Handler()

	// First request: validate + store + cache write.
	if rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", ""); rr.Code != 200 {
		t.Fatalf("first: code=%d", rr.Code)
	}
	firstTar := atomic.LoadInt32(&reg.tarCalls)
	firstPack := atomic.LoadInt32(&reg.packCalls)

	// Second request: trusted, served from cache (no upstream fetch).
	rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "")
	if rr.Code != 200 || rr.Body.String() != "TARBALL" {
		t.Fatalf("second: code=%d body=%q", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&reg.tarCalls) != firstTar || atomic.LoadInt32(&reg.packCalls) != firstPack {
		t.Errorf("second request hit upstream (tar=%d pack=%d); cache should serve", reg.tarCalls, reg.packCalls)
	}
}

func TestValidationRejectsFreshPackage(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	pack, raw := buildPackument(time.Now(), []byte("TARBALL")) // published now
	reg := &fakeReg{packument: pack, raw: raw, tarball: []byte("TARBALL")}
	srv := newTestServer(t, st, reg, testConfig(dir, "", 7)) // min_days=7
	h := srv.Handler()

	rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "")
	if rr.Code != 403 {
		t.Fatalf("code=%d want 403 (validation rejected); body=%q", rr.Code, rr.Body.String())
	}
	if len(st.records) != 0 {
		t.Errorf("rejected package must not be stored; records=%d", len(st.records))
	}
}

func TestTamperedCacheRefetches(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("GOOD")
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader(tarball))
	st := newMemStorage()
	st.records[key("testpkg", "1.0.0", "npm")] = storage.PackageRecord{
		Name: "testpkg", Version: "1.0.0", Registry: "npm", ValidationHash: goodHash, ValidatedAt: time.Now().UTC(),
	}
	pack, raw := buildPackument(time.Now().AddDate(0, 0, -30), tarball)
	reg := &fakeReg{packument: pack, raw: raw, tarball: tarball}
	srv := newTestServer(t, st, reg, testConfig(dir, "", 0))
	h := srv.Handler()

	// Pre-seed a corrupted cache file.
	corruptPath := filepath.Join(dir, "npm", "testpkg", "1.0.0.tgz")
	if err := os.MkdirAll(filepath.Dir(corruptPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corruptPath, []byte("CORRUPT"), 0o600); err != nil {
		t.Fatal(err)
	}

	rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "")
	if rr.Code != 200 || rr.Body.String() != "GOOD" {
		t.Fatalf("code=%d body=%q want 200/GOOD (refetched after corruption)", rr.Code, rr.Body.String())
	}
	if atomic.LoadInt32(&reg.tarCalls) < 1 {
		t.Errorf("expected an upstream refetch after cache corruption, tarCalls=%d", reg.tarCalls)
	}
	// Cache should now hold the good bytes.
	cached, err := os.ReadFile(corruptPath) //nolint:gosec // G304: corruptPath is under t.TempDir()
	if err != nil || string(cached) != "GOOD" {
		t.Errorf("cache not refreshed: %q err=%v", cached, err)
	}
}

func TestPackumentRouteRewritesTarball(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	pack, raw := buildPackument(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	reg := &fakeReg{packument: pack, raw: raw, tarball: []byte("TARBALL")}
	srv := newTestServer(t, st, reg, testConfig(dir, "", 0))
	h := srv.Handler()

	rr := doRequest(t, h, http.MethodGet, "/testpkg", "")
	if rr.Code != 200 {
		t.Fatalf("code=%d", rr.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v body=%q", err, rr.Body.String())
	}
	ver := doc["versions"].(map[string]any)["1.0.0"].(map[string]any)
	got := ver["dist"].(map[string]any)["tarball"].(string)
	// Should point at the proxy, ending in /testpkg/-/1.0.0
	if got == "http://fake/testpkg/-/testpkg-1.0.0.tgz" {
		t.Errorf("dist.tarball not rewritten: %q", got)
	}
	if !endsWith(got, "/testpkg/-/1.0.0") {
		t.Errorf("rewritten tarball unexpected: %q", got)
	}
}

func TestUpstreamNotFound(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	nfReg := &notFoundReg{}
	srv := newTestServer(t, st, nfReg, testConfig(dir, "", 0))
	h := srv.Handler()

	rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "")
	if rr.Code != 404 {
		t.Fatalf("code=%d want 404; body=%q", rr.Code, rr.Body.String())
	}
}

type notFoundReg struct{}

func (notFoundReg) FetchPackument(context.Context, string) (*registry.Packument, error) {
	return nil, registry.ErrNotFound
}
func (notFoundReg) FetchPackumentRaw(context.Context, string) ([]byte, error) {
	return nil, registry.ErrNotFound
}
func (notFoundReg) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, registry.ErrNotFound
}

func TestAuthProtectsTarball(t *testing.T) {
	dir := t.TempDir()
	st := newMemStorage()
	pack, raw := buildPackument(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	reg := &fakeReg{packument: pack, raw: raw, tarball: []byte("TARBALL")}
	srv := newTestServer(t, st, reg, testConfig(dir, "s3cret", 0))
	h := srv.Handler()

	if rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", ""); rr.Code != 401 {
		t.Errorf("no auth: code=%d want 401", rr.Code)
	}
	if rr := doRequest(t, h, http.MethodGet, "/testpkg/-/1.0.0", "Bearer s3cret"); rr.Code != 200 {
		t.Errorf("with auth: code=%d want 200", rr.Code)
	}
	if rr := doRequest(t, h, http.MethodGet, "/healthz", ""); rr.Code != 200 {
		t.Errorf("healthz: code=%d want 200 (exempt)", rr.Code)
	}
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
