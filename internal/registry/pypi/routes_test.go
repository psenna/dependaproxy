package pypi

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

type memStore struct {
	mu   sync.Mutex
	recs map[string]Record
}

func newMemStore() *memStore           { return &memStore{recs: map[string]Record{}} }
func pkey(name, ver, fn string) string { return name + "|" + ver + "|" + fn }

func (m *memStore) Get(_ context.Context, name, ver, fn string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[pkey(name, ver, fn)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}
func (m *memStore) Put(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[pkey(r.Name, r.Version, r.Filename)] = r
	return nil
}

// rawClient serves a trimmed Project, raw PEP 691 JSON, and file bytes.
type rawClient struct {
	project    *Project
	raw        []byte
	file       []byte
	indexCalls int32
	fileCalls  int32
}

func (c *rawClient) FetchIndex(_ context.Context, _ string) (*Project, error) {
	atomic.AddInt32(&c.indexCalls, 1)
	return c.project, nil
}
func (c *rawClient) FetchIndexRaw(_ context.Context, _ string, _ string) ([]byte, string, error) {
	return c.raw, acceptJSON, nil
}
func (c *rawClient) FetchFile(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	atomic.AddInt32(&c.fileCalls, 1)
	return io.NopCloser(bytes.NewReader(c.file)), int64(len(c.file)), nil
}

type notFoundClientP struct{}

func (notFoundClientP) FetchIndex(context.Context, string) (*Project, error) { return nil, ErrNotFound }
func (notFoundClientP) FetchIndexRaw(context.Context, string, string) ([]byte, string, error) {
	return nil, "", ErrNotFound
}
func (notFoundClientP) FetchFile(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, ErrNotFound
}

// --- project routing (issue #55) ---

// captureClient records the project name and the project key carried on the
// request context at fetch time, then serves canned upstream data.
type captureClient struct {
	project   *Project
	raw       []byte
	file      []byte
	mu        sync.Mutex
	rawPkg    string
	rawKey    string
	fileCalls int32
}

func (c *captureClient) FetchIndex(ctx context.Context, name string) (*Project, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rawPkg = name
	c.rawKey = pipeline.ProjectKeyFromContext(ctx)
	return c.project, nil
}
func (c *captureClient) FetchIndexRaw(ctx context.Context, name, _ string) ([]byte, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rawPkg = name
	c.rawKey = pipeline.ProjectKeyFromContext(ctx)
	return c.raw, acceptJSON, nil
}
func (c *captureClient) FetchFile(context.Context, string) (io.ReadCloser, int64, error) {
	atomic.AddInt32(&c.fileCalls, 1)
	return io.NopCloser(bytes.NewReader(c.file)), int64(len(c.file)), nil
}

func (c *captureClient) lastIndex() (pkg, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rawPkg, c.rawKey
}

// projKeyRecorder is a mutation middleware that captures the PipelineContext
// ProjectKey (and PkgName) seen by PreFetch on a file flow.
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

func TestPypiProjectKeySetOnContext(t *testing.T) {
	dir := t.TempDir()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &captureClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, newMemStore())
	rec := &projKeyRecorder{}
	a.mutation = pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{rec}}
	srv := newTestServer(t, a)

	// Project-scoped simple index: "/p/myproj" stripped, index for "testpkg".
	resp, err := http.Get(srv.URL + "/pypi/p/myproj/simple/testpkg/") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("index: code=%d want 200", resp.StatusCode)
	}
	pkg, key := c.lastIndex()
	if pkg != "testpkg" {
		t.Errorf("index fetched as %q, want %q (project prefix must be stripped)", pkg, "testpkg")
	}
	if key != "myproj" {
		t.Errorf("project key on index request context = %q, want %q", key, "myproj")
	}

	// Project-scoped file: the mutation PreFetch must see ctx.ProjectKey.
	resp, err = http.Get(srv.URL + "/pypi/p/myproj/files/testpkg/1.0.0/" + wheelFile) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "WHEEL" {
		t.Fatalf("file: code=%d body=%q want 200/WHEEL", resp.StatusCode, body)
	}
	key, pkg = rec.captured()
	if key != "myproj" {
		t.Errorf("ctx.ProjectKey = %q, want %q", key, "myproj")
	}
	if pkg != "testpkg" {
		t.Errorf("ctx.PkgName = %q, want %q", pkg, "testpkg")
	}
}

func TestPypiDefaultPathUnchanged(t *testing.T) {
	dir := t.TempDir()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &captureClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, newMemStore())
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/pypi/simple/testpkg/") //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("code=%d want 200", resp.StatusCode)
	}
	pkg, key := c.lastIndex()
	if pkg != "testpkg" {
		t.Errorf("index fetched as %q, want %q", pkg, "testpkg")
	}
	if key != "" {
		t.Errorf("project key on default path = %q, want \"\"", key)
	}
}

func pyYamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

func newTestAdapter(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store) *pypiAdapter {
	t.Helper()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{{Type: "min-publication-age", Params: pyYamlNode(fmt.Sprintf("min_days: %d", minDays))}})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: pyYamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, _ := reg.BuildMutation(nil)
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	var cache evicter
	if e, ok := retrieval.Head.(evicter); ok {
		cache = e
	}
	return &pypiAdapter{
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

func newTestServer(t *testing.T, a *pypiAdapter) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.StripPrefix(a.prefix, a.Handler()))
	t.Cleanup(srv.Close)
	return srv
}

// fetchViaProxy mimics pip: GET the simple index -> read files[0].url -> GET it.
func fetchViaProxy(t *testing.T, base, pkg string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(base + "/simple/" + pkg + "/") //nolint:gosec // G107: proxy URL under test
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
	files := doc["files"].([]any)
	url := files[0].(map[string]any)["url"].(string)
	tr, err := http.Get(url) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Body.Close() }()
	body, _ := io.ReadAll(tr.Body)
	return tr.StatusCode, body
}

const wheelFile = "testpkg-1.0.0-py3-none-any.whl"

func buildPack(pub time.Time, file []byte) (*Project, []byte) {
	proj := &Project{Name: "testpkg", Files: []File{{Filename: wheelFile, URL: "http://up/f.whl", RequiresPython: ">=3.7", UploadTime: pub}}}
	raw := []byte(`{"meta":{"api-version":"1.0"},"name":"testpkg","files":[{"filename":"` + wheelFile + `","url":"http://up/f.whl","requires-python":">=3.7","upload-time":"` + pub.Format(time.RFC3339Nano) + `"}]}`)
	return proj, raw
}

func TestPypiIndexRewrites(t *testing.T) {
	dir := t.TempDir()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, newMemStore())
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/pypi/simple/testpkg/") //nolint:gosec // G107
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	got := doc["files"].([]any)[0].(map[string]any)["url"].(string)
	if !strings.HasSuffix(got, "/pypi/files/testpkg/1.0.0/"+wheelFile) {
		t.Errorf("rewritten url = %q", got)
	}
}

func TestPypiUntrustedValidatesStoresServes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, store)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("code=%d body=%q", code, body)
	}
	if len(store.recs) != 1 {
		t.Fatalf("expected stored record, got %d", len(store.recs))
	}
	r := store.recs[pkey("testpkg", "1.0.0", wheelFile)]
	if r.FileType != "wheel" || r.PythonTag != "py3" || r.AbiTag != "none" || r.PlatformTag != "any" {
		t.Errorf("stored tags = %+v", r)
	}
}

func TestPypiTrustedServedFromCache(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, store)
	srv := newTestServer(t, a)

	if code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg"); code != 200 {
		t.Fatalf("first: code=%d", code)
	}
	first := atomic.LoadInt32(&c.fileCalls)
	if code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg"); code != 200 || string(body) != "WHEEL" {
		t.Fatalf("second: code=%d body=%q", code, body)
	}
	if atomic.LoadInt32(&c.fileCalls) != first {
		t.Errorf("second request hit upstream (file=%d -> %d); cache should serve", first, c.fileCalls)
	}
}

func TestPypiValidationRejectsFresh(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	proj, raw := buildPack(time.Now(), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 7, c, store)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 403 {
		t.Fatalf("code=%d want 403", code)
	}
	if len(store.recs) != 0 {
		t.Errorf("rejected file must not be stored; recs=%d", len(store.recs))
	}
}

func TestPypiCorruptDBHash502(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	store.recs[pkey("testpkg", "1.0.0", wheelFile)] = Record{Name: "testpkg", Version: "1.0.0", Filename: wheelFile, Sha256: "deadbeef", ValidatedAt: time.Now().UTC()}
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}
	a := newTestAdapter(t, "/pypi", dir, 0, c, store)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 502 {
		t.Fatalf("code=%d want 502 (integrity mismatch)", code)
	}
}

func TestPypiTamperedCacheRefetches(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("GOOD")
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader(tarball))
	store := newMemStore()
	store.recs[pkey("testpkg", "1.0.0", wheelFile)] = Record{Name: "testpkg", Version: "1.0.0", Filename: wheelFile, Sha256: goodHash, ValidatedAt: time.Now().UTC()}
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	c := &rawClient{project: proj, raw: raw, file: tarball}
	a := newTestAdapter(t, "/pypi", dir, 0, c, store)
	srv := newTestServer(t, a)

	corrupt := filepath.Join(dir, "pypi", "testpkg", "1.0.0", wheelFile+".bin")
	if err := os.MkdirAll(filepath.Dir(corrupt), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt, []byte("CORRUPT"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "GOOD" {
		t.Fatalf("code=%d body=%q want 200/GOOD", code, body)
	}
	if atomic.LoadInt32(&c.fileCalls) < 1 {
		t.Errorf("expected refetch, fileCalls=%d", c.fileCalls)
	}
}

func TestPypiUpstreamNotFound(t *testing.T) {
	dir := t.TempDir()
	a := newTestAdapter(t, "/pypi", dir, 0, notFoundClientP{}, newMemStore())
	srv := newTestServer(t, a)
	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "nope")
	if code != 404 {
		t.Fatalf("code=%d want 404", code)
	}
}
