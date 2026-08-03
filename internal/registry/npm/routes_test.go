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
	"github.com/psenna/dependaproxy/internal/project"
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

// fakeProjectStore is an in-memory project.Store used by adapter tests: every
// key resolves to ErrProjectNotFound so the resolver falls back to the global
// pipelines (byte-identical to the pre-project-routing default path).
type fakeProjectStore struct{}

func (fakeProjectStore) Get(_ context.Context, _ string) (project.ProjectConfig, error) {
	return project.ProjectConfig{}, project.ErrProjectNotFound
}
func (fakeProjectStore) Put(context.Context, project.ProjectConfig) error { return nil }
func (fakeProjectStore) List(context.Context) ([]project.ProjectConfig, error) {
	return nil, nil
}
func (fakeProjectStore) Delete(context.Context, string) error { return nil }

// newTestAdapter builds an npmAdapter wired with a memStore + fake client + the
// configured pipelines (localcache(dir) -> upstream -> min-pub-age), all as the
// global (default) Resolved.
func newTestAdapter(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store) *npmAdapter {
	t.Helper()
	return newTestAdapterWithGlobal(t, prefix, dir, minDays, client, store, nil)
}

// newTestAdapterWithGlobal is newTestAdapter with an optional global Resolved
// override: any zero chain in the override is filled from the locally-built
// default pipelines, so callers can replace just one chain (e.g. Mutation) while
// keeping the rest byte-identical.
func newTestAdapterWithGlobal(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store, global *project.Resolved) *npmAdapter {
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

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}
	if global == nil {
		global = &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	}
	if global.Validation.Chain == nil {
		global.Validation = validation
	}
	if global.Retrieval.Head == nil {
		global.Retrieval = retrieval
		global.Cache = cache
	}
	if global.Mutation.Chain == nil {
		global.Mutation = mp
	}
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	return &npmAdapter{
		prefix:   prefix,
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
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

// --- project routing (issue #55) ---

// captureClient records the pkg name and the project key carried on the request
// context at fetch time, then serves canned upstream data.
type captureClient struct {
	pack         *Packument
	raw          []byte
	tarball      []byte
	mu           sync.Mutex
	packumentPkg string
	packumentKey string
	tarCalls     int32
}

func (c *captureClient) FetchPackument(context.Context, string) (*Packument, error) {
	return c.pack, nil
}
func (c *captureClient) FetchPackumentRaw(ctx context.Context, name string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packumentPkg = name
	c.packumentKey = pipeline.ProjectKeyFromContext(ctx)
	return c.raw, nil
}
func (c *captureClient) FetchTarball(context.Context, string) (io.ReadCloser, int64, error) {
	atomic.AddInt32(&c.tarCalls, 1)
	return io.NopCloser(bytes.NewReader(c.tarball)), int64(len(c.tarball)), nil
}

func (c *captureClient) lastPackument() (pkg, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.packumentPkg, c.packumentKey
}

// projKeyRecorder is a mutation middleware that captures the PipelineContext
// ProjectKey (and PkgName) seen by PreFetch on a tarball flow.
type projKeyRecorder struct {
	mu  sync.Mutex
	key string
	pkg string
}

func (*projKeyRecorder) Name() string { return "project-key-recorder" }
func (r *projKeyRecorder) PreFetch(ctx *pipeline.PipelineContext) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.key = ctx.ProjectKey
	r.pkg = ctx.PkgName
	return nil
}
func (*projKeyRecorder) PostFetch(*pipeline.PipelineContext) error { return nil }

func (r *projKeyRecorder) captured() (key, pkg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.key, r.pkg
}

func TestNpmProjectKeySetOnContext(t *testing.T) {
	dir := t.TempDir()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	c := &captureClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 0, c, newMemStore())
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/npm/p/myproj/testpkg") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("code=%d want 200", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)

	pkg, key := c.lastPackument()
	if pkg != "testpkg" {
		t.Errorf("packument fetched as %q, want %q (project prefix must be stripped)", pkg, "testpkg")
	}
	if key != "myproj" {
		t.Errorf("project key on request context = %q, want %q", key, "myproj")
	}
}

func TestNpmProjectTarballSetsKey(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	c := &captureClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	rec := &projKeyRecorder{}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{rec}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, c, store, global)
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/npm/p/myproj/testpkg/-/1.0.0") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "TARBALL" {
		t.Fatalf("code=%d body=%q want 200/TARBALL", resp.StatusCode, body)
	}

	key, pkg := rec.captured()
	if key != "myproj" {
		t.Errorf("ctx.ProjectKey = %q, want %q", key, "myproj")
	}
	if pkg != "testpkg" {
		t.Errorf("ctx.PkgName = %q, want %q", pkg, "testpkg")
	}
}

func TestNpmPackagePTarballUnchanged(t *testing.T) {
	dir := t.TempDir()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	c := &captureClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	rec := &projKeyRecorder{}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{rec}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, c, newMemStore(), global)
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/npm/p/-/lodash-1.0.0.tgz") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// The "p/-/" path is the npm registry's own package-"p" tarball namespace;
	// it must route to handleTarball with pkg "p" and NOT set a project key.
	key, pkg := rec.captured()
	if key != "" {
		t.Errorf("ctx.ProjectKey = %q, want \"\" (dash key must not scope)", key)
	}
	if pkg != "p" {
		t.Errorf("ctx.PkgName = %q, want %q (p/-/ tarball routes to package p)", pkg, "p")
	}
}

func TestNpmScopedPackageUnchanged(t *testing.T) {
	dir := t.TempDir()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	c := &captureClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newTestAdapter(t, "/npm", dir, 0, c, newMemStore())
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/npm/@scope/pkg") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("code=%d want 200", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)

	pkg, key := c.lastPackument()
	if pkg != "@scope/pkg" {
		t.Errorf("packument fetched as %q, want %q", pkg, "@scope/pkg")
	}
	if key != "" {
		t.Errorf("project key on request context = %q, want \"\"", key)
	}
}
