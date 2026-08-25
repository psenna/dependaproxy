package goproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// newTestAdapter builds a goproxyAdapter wired to a real client for upstream.
func newTestAdapter(t *testing.T, prefix, upstream string) *goproxyAdapter {
	t.Helper()
	client, err := New(upstream, nil)
	if err != nil {
		t.Fatal(err)
	}
	return newTestAdapterWithStore(t, prefix, client, newMemStore())
}

// newTestAdapterWithStore builds a goproxyAdapter with a canned client + store
// and the v1 pipelines (upstream-registry -> noop mutation, empty validation).
func newTestAdapterWithStore(t *testing.T, prefix string, client RegistryClient, store Store) *goproxyAdapter {
	t.Helper()
	return newTestAdapterWithGlobal(t, prefix, client, store, nil)
}

// newTestAdapterWithGlobal is newTestAdapterWithStore with an optional global
// Resolved override: any zero chain in the override is filled from the locally
// built default pipelines, so callers can replace just one chain (e.g.
// Validation) while keeping the rest byte-identical.
func newTestAdapterWithGlobal(t *testing.T, prefix string, client RegistryClient, store Store, global *project.Resolved) *goproxyAdapter {
	t.Helper()
	reg := pipeline.NewRegistry()
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation(nil)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{{Type: "upstream-registry"}})
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
	resolver := project.NewResolver("goproxy", reg, fakeProjectStore{}, global)
	return &goproxyAdapter{
		prefix:   prefix,
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
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

// memStore is an in-process goproxy Store for tests. accessed records any
// storage access (Get or Put) so metadata tests can assert the store is never
// touched; puts counts the Put calls so trusted-path tests can assert no
// re-storage.
type memStore struct {
	mu       sync.Mutex
	recs     map[string]Record
	accessed bool
	puts     int
}

func newMemStore() *memStore { return &memStore{recs: map[string]Record{}} }
func k(projectKey, module, ver string) string {
	return projectKey + "|" + module + "|" + ver
}

func (m *memStore) Get(_ context.Context, projectKey, module, ver string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessed = true
	r, ok := m.recs[k(projectKey, module, ver)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return r, nil
}
func (m *memStore) Put(_ context.Context, r Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessed = true
	m.puts++
	m.recs[k(r.ProjectKey, r.ModulePath, r.Version)] = r
	return nil
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

// fakeClient serves canned GOPROXY responses and counts zip fetches.
type fakeClient struct {
	info     *Info
	zip      []byte
	mod      []byte
	list     []string
	latest   *Info
	notFound bool
	zipCalls int32
}

func newFakeClient() *fakeClient {
	return &fakeClient{
		info:   &Info{Version: testVersion, Time: time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)},
		zip:    []byte(testZipBody),
		mod:    []byte(testModBody),
		list:   []string{"v1.0.0", "v1.1.0"},
		latest: &Info{Version: "v1.1.0", Time: time.Date(2021, 2, 1, 0, 0, 0, 0, time.UTC)},
	}
}

func (c *fakeClient) FetchList(_ context.Context, _ string) ([]string, error) {
	if c.notFound {
		return nil, ErrNotFound
	}
	return c.list, nil
}
func (c *fakeClient) FetchInfo(_ context.Context, _ string, _ string) (*Info, error) {
	if c.notFound {
		return nil, ErrNotFound
	}
	return c.info, nil
}
func (c *fakeClient) FetchMod(_ context.Context, _ string, _ string) ([]byte, error) {
	if c.notFound {
		return nil, ErrNotFound
	}
	return c.mod, nil
}
func (c *fakeClient) FetchZip(_ context.Context, _ string, _ string) (io.ReadCloser, int64, error) {
	if c.notFound {
		return nil, 0, ErrNotFound
	}
	atomic.AddInt32(&c.zipCalls, 1)
	return io.NopCloser(bytes.NewReader(c.zip)), int64(len(c.zip)), nil
}
func (c *fakeClient) FetchLatest(_ context.Context, _ string) (*Info, error) {
	if c.notFound {
		return nil, ErrNotFound
	}
	return c.latest, nil
}

// flipClient is a fakeClient that returns a CORRUPT zip on the first FetchZip
// call and the GOOD zip afterwards, simulating a tampered first read.
type flipClient struct {
	fakeClient
	mu      sync.Mutex
	corrupt []byte
	flipped bool
}

func (c *flipClient) FetchZip(_ context.Context, _ string, _ string) (io.ReadCloser, int64, error) {
	if c.notFound {
		return nil, 0, ErrNotFound
	}
	atomic.AddInt32(&c.zipCalls, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.flipped {
		c.flipped = true
		return io.NopCloser(bytes.NewReader(c.corrupt)), int64(len(c.corrupt)), nil
	}
	return io.NopCloser(bytes.NewReader(c.zip)), int64(len(c.zip)), nil
}

// fakeDependencyTracker records Tracked records; it never flushes to a DB.
type fakeDependencyTracker struct {
	mu      sync.Mutex
	records []project.DependencyRecord
}

func (f *fakeDependencyTracker) Track(rec project.DependencyRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
}
func (f *fakeDependencyTracker) Start(context.Context) error    { return nil }
func (f *fakeDependencyTracker) Shutdown(context.Context) error { return nil }

func (f *fakeDependencyTracker) all() []project.DependencyRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]project.DependencyRecord(nil), f.records...)
}

// recordingValidation counts Validate calls so tests can assert that only the
// untrusted path runs the validation chain (the trusted path serves from the
// stored hash and never re-validates).
type recordingValidation struct {
	mu          sync.Mutex
	validations int32
}

func (r *recordingValidation) Name() string { return "recording-validation" }
func (r *recordingValidation) Validate(_ *pipeline.PipelineContext) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validations++
	return nil
}

func (r *recordingValidation) count() int32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.validations
}

// --- pass-through metadata routes ---

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

// --- validated-module trust flow (.zip) ---

func TestGoproxyZipUntrustedValidatesStoresServes(t *testing.T) {
	store := newMemStore()
	client := newFakeClient()
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	srv := newTestServer(t, a)

	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/zip" {
		t.Errorf("content-type = %q", ct)
	}
	if len(store.recs) != 1 {
		t.Fatalf("expected stored record, got %d", len(store.recs))
	}
	want, _, _ := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	if store.recs[k("", testModule, testVersion)].ValidationHash != want {
		t.Error("stored hash mismatch")
	}
}

func TestGoproxyZipTrustedServedFromHash(t *testing.T) {
	store := newMemStore()
	client := newFakeClient()
	rec := &recordingValidation{}
	global := &project.Resolved{Validation: pipeline.ValidationPipeline{Chain: []pipeline.ValidationMiddleware{rec}}}
	a := newTestAdapterWithGlobal(t, "/goproxy", client, store, global)
	srv := newTestServer(t, a)

	// First fetch: untrusted path — validates once, stores the sha256 anchor.
	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("first: code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if got := rec.count(); got != 1 {
		t.Errorf("validations after first fetch = %d, want 1 (untrusted path)", got)
	}
	if store.puts != 1 {
		t.Errorf("puts after first fetch = %d, want 1", store.puts)
	}

	// Second fetch: trusted path — no cache middleware, so upstream is re-fetched
	// and the body verified against the stored hash, but validation must NOT
	// re-run and no new record may be written.
	code, _, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("second: code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if got := rec.count(); got != 1 {
		t.Errorf("validations after second fetch = %d, want 1 (trusted path must not re-validate)", got)
	}
	if store.puts != 1 {
		t.Errorf("puts after second fetch = %d, want 1 (trusted path must not re-store)", store.puts)
	}
	if len(store.recs) != 1 {
		t.Errorf("store recs = %d, want 1", len(store.recs))
	}
}

func TestGoproxyZipTamperedRefetches(t *testing.T) {
	store := newMemStore()
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	store.recs[k("", testModule, testVersion)] = Record{ModulePath: testModule, Version: testVersion, ValidationHash: goodHash, ValidatedAt: time.Now().UTC()}
	client := &flipClient{fakeClient: *newFakeClient(), corrupt: []byte("CORRUPT")}
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if atomic.LoadInt32(&client.zipCalls) < 2 {
		t.Errorf("zipCalls=%d want >= 2 (verifyOrEvict must refetch and reverify)", client.zipCalls)
	}
}

func TestGoproxyZipPersistentMismatch502(t *testing.T) {
	store := newMemStore()
	store.recs[k("", testModule, testVersion)] = Record{ModulePath: testModule, Version: testVersion, ValidationHash: "deadbeef", ValidatedAt: time.Now().UTC()}
	client := newFakeClient()
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusBadGateway {
		t.Fatalf("code=%d want 502 (integrity mismatch)", code)
	}
	if !strings.Contains(string(body), "integrity mismatch") {
		t.Errorf("body = %q", body)
	}
}

func TestGoproxyZipUpstreamNotFound404(t *testing.T) {
	store := newMemStore()
	client := &fakeClient{notFound: true}
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	srv := newTestServer(t, a)

	code, _, _ := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusNotFound {
		t.Fatalf("code=%d want 404", code)
	}
}

func TestGoproxyMetadataStillProxiedNoStorage(t *testing.T) {
	store := newMemStore()
	client := newFakeClient()
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	srv := newTestServer(t, a)

	// list
	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/list")
	if code != http.StatusOK || string(body) != testListBody {
		t.Fatalf("list: code=%d body=%q", code, body)
	}
	// info
	code, _, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".info")
	if code != http.StatusOK {
		t.Fatalf("info: code=%d", code)
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf("info decode: %v", err)
	}
	if info.Version != testVersion {
		t.Errorf("info version = %q", info.Version)
	}
	// mod
	code, _, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".mod")
	if code != http.StatusOK || string(body) != testModBody {
		t.Fatalf("mod: code=%d body=%q", code, body)
	}
	// latest
	code, _, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@latest")
	if code != http.StatusOK {
		t.Fatalf("latest: code=%d", code)
	}
	var latest Info
	if err := json.Unmarshal(body, &latest); err != nil {
		t.Fatalf("latest decode: %v", err)
	}
	if latest.Version != "v1.1.0" {
		t.Errorf("latest version = %q", latest.Version)
	}

	if store.accessed {
		t.Fatal("metadata handlers must not access storage")
	}
}

func TestGoproxyProjectZipTracked(t *testing.T) {
	store := newMemStore()
	client := newFakeClient()
	tracker := &fakeDependencyTracker{}
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	a.tracker = tracker
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/p/myproj/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	recs := tracker.all()
	if len(recs) != 1 {
		t.Fatalf("tracked %d records, want 1", len(recs))
	}
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	got := recs[0]
	if got.ProjectKey != "myproj" || got.Registry != "goproxy" || got.Pkg != testModule ||
		got.Version != testVersion || got.ArtifactID != "" || got.SHA256 != wantHash {
		t.Errorf("record = %+v", got)
	}
}

func TestGoproxyDefaultZipNotTracked(t *testing.T) {
	store := newMemStore()
	client := newFakeClient()
	tracker := &fakeDependencyTracker{}
	a := newTestAdapterWithStore(t, "/goproxy", client, store)
	a.tracker = tracker
	srv := newTestServer(t, a)

	code, _, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if recs := tracker.all(); len(recs) != 0 {
		t.Fatalf("tracked %d records on default path, want 0 (ProjectKey==\"\" short-circuit)", len(recs))
	}
}
