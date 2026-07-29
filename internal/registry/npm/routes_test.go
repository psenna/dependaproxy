package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// memStore is an in-process npm Store for tests.
type memStore struct {
	mu   sync.Mutex
	recs map[string]Record
}

func newMemStore() *memStore    { return &memStore{recs: map[string]Record{}} }
func k(name, ver string) string { return name + "|" + ver }

func (m *memStore) Get(_ context.Context, name, ver string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[k(name, ver)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}
func (m *memStore) Put(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[k(r.Name, r.Version)] = r
	return nil
}

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

// newTestAdapter builds an npmAdapter wired with a memStore + fake client + the
// configured pipelines (localcache(dir) -> upstream -> min-pub-age).
func newTestAdapter(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store) *npmAdapter {
	t.Helper()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{{Type: "min-publication-age", Params: yamlNode(fmt.Sprintf("min_days: %d", minDays))}})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: yamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, err := reg.BuildMutation(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	var cache evicter
	if e, ok := retrieval.Head.(evicter); ok {
		cache = e
	}
	return &npmAdapter{
		prefix:     prefix,
		storage:    store,
		client:     client,
		validation: validation,
		retrieval:  retrieval,
		mutation:   mp,
		cache:      cache,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:        func() time.Time { return time.Now().UTC() },
	}
}

func newTestServer(t *testing.T, a *npmAdapter) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.StripPrefix(a.prefix, a.Handler()))
	t.Cleanup(srv.Close)
	return srv
}

// fetchViaProxy mimics npm: GET packument -> read rewritten dist.tarball -> GET it.
func fetchViaProxy(t *testing.T, base, pkg, version string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(base + "/" + pkg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	tb := doc["versions"].(map[string]any)[version].(map[string]any)["dist"].(map[string]any)["tarball"].(string)
	tr, err := http.Get(tb) //nolint:gosec // G107: tb is the proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Body.Close() }()
	body, _ := io.ReadAll(tr.Body)
	return tr.StatusCode, body
}

func buildPack(pub time.Time, tarball []byte) (*Packument, []byte) {
	p := &Packument{
		Name:     "testpkg",
		Versions: map[string]Version{"1.0.0": {Version: "1.0.0", Dist: Dist{Tarball: "http://up/testpkg/-/testpkg-1.0.0.tgz", Integrity: "sha512-x"}}},
		Time:     map[string]time.Time{"1.0.0": pub},
		DistTags: map[string]string{"latest": "1.0.0"},
	}
	raw := []byte(`{"name":"testpkg","versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"http://up/testpkg/-/testpkg-1.0.0.tgz","integrity":"sha512-x"},"dependencies":{"left-pad":"1.0.0"}}},"time":{"1.0.0":"` + pub.Format(time.RFC3339Nano) + `"},"dist-tags":{"latest":"1.0.0"}}`)
	return p, raw
}

func TestNpmUntrustedValidatesStoresServes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 0, client, store)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q", code, body)
	}
	if len(store.recs) != 1 {
		t.Fatalf("expected stored record, got %d", len(store.recs))
	}
	want, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("TARBALL")))
	if store.recs[k("testpkg", "1.0.0")].ValidationHash != want {
		t.Error("stored hash mismatch")
	}
}

func TestNpmTrustedServedFromCache(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 0, client, store)
	srv := newTestServer(t, a)

	if code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != 200 {
		t.Fatalf("first: code=%d", code)
	}
	firstTar := atomic.LoadInt32(&client.tarCalls)
	if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != 200 || string(body) != "TARBALL" {
		t.Fatalf("second: code=%d body=%q", code, body)
	}
	if atomic.LoadInt32(&client.tarCalls) != firstTar {
		t.Errorf("second request hit upstream (tar=%d -> %d); cache should serve", firstTar, client.tarCalls)
	}
}

func TestNpmValidationRejectsFresh(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now(), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 7, client, store)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 403 {
		t.Fatalf("code=%d want 403", code)
	}
	if len(store.recs) != 0 {
		t.Errorf("rejected package must not be stored; recs=%d", len(store.recs))
	}
}

func TestNpmTamperedCacheRefetches(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("GOOD")
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader(tarball))
	store := newMemStore()
	store.recs[k("testpkg", "1.0.0")] = Record{Name: "testpkg", Version: "1.0.0", ValidationHash: goodHash, ValidatedAt: time.Now().UTC()}
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	client := &rawClient{pack: pack, raw: raw, tarball: tarball}
	a := newTestAdapter(t, "/npm", dir, 0, client, store)
	srv := newTestServer(t, a)

	corrupt := filepath.Join(dir, "npm", "testpkg", "1.0.0.bin")
	if err := os.MkdirAll(filepath.Dir(corrupt), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt, []byte("CORRUPT"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "GOOD" {
		t.Fatalf("code=%d body=%q want 200/GOOD", code, body)
	}
	if atomic.LoadInt32(&client.tarCalls) < 1 {
		t.Errorf("expected refetch, tarCalls=%d", client.tarCalls)
	}
}

func TestNpmCorruptDBHash502(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("GOOD")
	store := newMemStore()
	store.recs[k("testpkg", "1.0.0")] = Record{Name: "testpkg", Version: "1.0.0", ValidationHash: "deadbeef", ValidatedAt: time.Now().UTC()}
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	client := &rawClient{pack: pack, raw: raw, tarball: tarball}
	a := newTestAdapter(t, "/npm", dir, 0, client, store)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 502 {
		t.Fatalf("code=%d want 502 (integrity mismatch)", code)
	}
}

func TestNpmPackumentRewrites(t *testing.T) {
	dir := t.TempDir()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 0, client, newMemStore())
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/npm/testpkg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	got := doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["dist"].(map[string]any)["tarball"].(string)
	if !strings.HasSuffix(got, "/npm/testpkg/-/1.0.0") {
		t.Errorf("rewritten tarball = %q", got)
	}
}

func TestNpmUpstreamNotFound(t *testing.T) {
	dir := t.TempDir()
	client := &notFoundClient{}
	a := newTestAdapter(t, "/npm", dir, 0, client, newMemStore())
	srv := newTestServer(t, a)
	code, _ := fetchViaProxy(t, srv.URL+"/npm", "nope", "1.0.0")
	if code != 404 {
		t.Fatalf("code=%d want 404", code)
	}
}

// rawClient serves a trimmed packument, a raw packument, and a tarball.
type rawClient struct {
	pack      *Packument
	raw       []byte
	tarball   []byte
	packCalls int32
	tarCalls  int32
}

func (c *rawClient) FetchPackument(_ context.Context, _ string) (*Packument, error) {
	atomic.AddInt32(&c.packCalls, 1)
	return c.pack, nil
}
func (c *rawClient) FetchPackumentRaw(_ context.Context, _ string) ([]byte, error) { return c.raw, nil }
func (c *rawClient) FetchTarball(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	atomic.AddInt32(&c.tarCalls, 1)
	return io.NopCloser(bytes.NewReader(c.tarball)), int64(len(c.tarball)), nil
}

type notFoundClient struct{}

func (notFoundClient) FetchPackument(context.Context, string) (*Packument, error) {
	return nil, ErrNotFound
}
func (notFoundClient) FetchPackumentRaw(context.Context, string) ([]byte, error) {
	return nil, ErrNotFound
}
func (notFoundClient) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, ErrNotFound
}
