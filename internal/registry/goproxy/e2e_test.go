package goproxy

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/server"
	"github.com/psenna/dependaproxy/internal/storage/db"
)

// newE2EAdapter builds a goproxyAdapter wired to a REAL goproxy client and the
// full v1 middleware set (min-publication-age, cve-check, cve-check-retrieval,
// local-disk-cache, s3-cache, upstream-registry, noop mutation), so the e2e
// tests drive the real request/retrieval/validation flow
// against an httptest upstream. The config-driven goproxy.Factory is NOT used
// here because it needs a *sql.DB (OpenStorage); the postgres-gated sub-test
// exercises the real Factory via server.New.
func newE2EAdapter(t *testing.T, prefix, upstream string, store Store, dir string, validation []config.Middleware) *goproxyAdapter {
	t.Helper()
	client, err := New(upstream, nil)
	if err != nil {
		t.Fatal(err)
	}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("s3-cache", s3cache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validationPipeline, err := reg.BuildValidation(validation)
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
	global := &project.Resolved{Validation: validationPipeline, Retrieval: retrieval, Mutation: mp, Cache: cache}
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

// osvHitServer is a fake OSV /v1/query endpoint that always reports a known
// vulnerability (cve-check maps the goproxy registry to OSV's "Go" ecosystem).
func osvHitServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2026-0001", "summary": "test vuln"}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newUpstreamAt mirrors newUpstream (client_test.go) but serves the .info and
// @latest documents with the given publication Time — for the min-publication-age
// gate, which reads the .info Time stashed by the upstream-registry retrieval.
func newUpstreamAt(t *testing.T, infoTime time.Time) (*httptest.Server, *string) {
	t.Helper()
	var lastPath string
	info := fmt.Sprintf(`{"Version":%q,"Time":%q}`, testVersion, infoTime.UTC().Format(time.RFC3339))
	latest := fmt.Sprintf(`{"Version":"v1.1.0","Time":%q}`, infoTime.UTC().Format(time.RFC3339))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastPath = r.URL.Path
		switch r.URL.Path {
		case "/" + testModuleEscaped + "/@v/list":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, testListBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, info)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".mod":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, testModBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, testZipBody)
		case "/" + testModuleEscaped + "/@latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, latest)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &lastPath
}

// goproxyZipURL returns the proxy .zip URL for the test module/version.
func goproxyZipURL(base string) string {
	return base + "/goproxy/" + testModuleEscaped + "/@v/" + testVersion + ".zip"
}

// authedGet performs an authed GET against the httptest server.
func authedGet(t *testing.T, base, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil) //nolint:gosec // G704: test URL
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test URL
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// authedDo performs an authed HTTP request against the httptest server.
func authedDo(t *testing.T, base, method, path, body, token string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rdr) //nolint:gosec // G704: test URL
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test URL
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// --- e2e: GOPROXY protocol endpoints through a real client + fake upstream ---

func TestGoproxyE2EProtocolEndpoints(t *testing.T) {
	up, _ := newUpstream(t)
	srv := newTestServer(t, newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), nil))

	// .info -> application/json {Version,Time}
	code, hdr, body := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".info")
	if code != http.StatusOK {
		t.Fatalf(".info: status = %d want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf(".info content-type = %q", ct)
	}
	var info Info
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatalf(".info decode: %v", err)
	}
	if info.Version != testVersion {
		t.Errorf(".info version = %q want %q", info.Version, testVersion)
	}
	want := time.Date(2021, 1, 15, 10, 0, 0, 0, time.UTC)
	if !info.Time.Equal(want) {
		t.Errorf(".info time = %v want %v", info.Time, want)
	}

	// .mod -> text/plain, body == testModBody
	code, hdr, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".mod")
	if code != http.StatusOK {
		t.Fatalf(".mod: status = %d want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf(".mod content-type = %q", ct)
	}
	if string(body) != testModBody {
		t.Errorf(".mod body = %q want %q", body, testModBody)
	}

	// .zip -> application/zip + Content-Length + body == testZipBody
	code, hdr, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip")
	if code != http.StatusOK {
		t.Fatalf(".zip: status = %d want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/zip" {
		t.Errorf(".zip content-type = %q", ct)
	}
	if cl := hdr.Get("Content-Length"); cl != "9" {
		t.Errorf(".zip content-length = %q want 9", cl)
	}
	if string(body) != testZipBody {
		t.Errorf(".zip body = %q want %q", body, testZipBody)
	}

	// @v/list -> text/plain version list
	code, hdr, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/list")
	if code != http.StatusOK {
		t.Fatalf("list: status = %d want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("list content-type = %q", ct)
	}
	if string(body) != testListBody {
		t.Errorf("list body = %q want %q", body, testListBody)
	}

	// @latest -> application/json
	code, hdr, body = get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@latest")
	if code != http.StatusOK {
		t.Fatalf("@latest: status = %d want 200", code)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json" {
		t.Errorf("@latest content-type = %q", ct)
	}
	var latest Info
	if err := json.Unmarshal(body, &latest); err != nil {
		t.Fatalf("@latest decode: %v", err)
	}
	if latest.Version != "v1.1.0" {
		t.Errorf("@latest version = %q want v1.1.0", latest.Version)
	}
}

func TestGoproxyE2EUpstreamNotFound(t *testing.T) {
	up, _ := newUpstream(t)
	srv := newTestServer(t, newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), nil))

	for _, p := range []string{
		"/goproxy/example.com/missing/@v/list",
		"/goproxy/example.com/missing/@v/v1.0.0.info",
		"/goproxy/example.com/missing/@v/v1.0.0.mod",
		"/goproxy/example.com/missing/@v/v1.0.0.zip",
		"/goproxy/example.com/missing/@latest",
	} {
		if code, _, _ := get(t, srv.URL+p); code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d want 404", p, code)
		}
	}

	// Invalid escaped path: uppercase without a "!" escape is a 400.
	code, _, body := get(t, srv.URL+"/goproxy/github.com/Azure/azure-sdk-for-go/@v/list")
	if code != http.StatusBadRequest {
		t.Fatalf("invalid escaped path: status = %d want 400", code)
	}
	if !strings.Contains(string(body), "invalid module path") {
		t.Errorf("invalid escaped path body = %q", body)
	}
}

// --- e2e: trust flow (validate -> store sha256 -> serve; tamper -> evict+refetch) ---

func TestGoproxyE2ETrustFlowStoresAndServes(t *testing.T) {
	up, _ := newUpstream(t)
	store := newMemStore()
	srv := newTestServer(t, newE2EAdapter(t, "/goproxy", up.URL, store, t.TempDir(), nil))

	// First (untrusted) fetch: validated, stored as a sha256 trust anchor.
	if code, _, body := get(t, goproxyZipURL(srv.URL)); code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("first fetch: code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if len(store.recs) != 1 {
		t.Fatalf("store recs = %d want 1", len(store.recs))
	}
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	if got := store.recs[k(testModule, testVersion)].ValidationHash; got != wantHash {
		t.Errorf("stored hash = %q want %q", got, wantHash)
	}

	// Second (trusted) fetch: same body, served from the stored hash — no re-store.
	if code, _, body := get(t, goproxyZipURL(srv.URL)); code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("second fetch: code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if store.puts != 1 {
		t.Errorf("store puts = %d want 1 (trusted path must not re-store)", store.puts)
	}
}

func TestGoproxyE2ETamperedCacheEvictsAndRefetches(t *testing.T) {
	var zipCalls int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, testInfoBody)
		case "/" + testModuleEscaped + "/@v/" + testVersion + ".zip":
			atomic.AddInt32(&zipCalls, 1)
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, testZipBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(up.Close)

	dir := t.TempDir()
	store := newMemStore()
	srv := newTestServer(t, newE2EAdapter(t, "/goproxy", up.URL, store, dir, nil))

	// First (untrusted) fetch: validates, stores the record, writes the cache file.
	if code, _, body := get(t, goproxyZipURL(srv.URL)); code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("first fetch: code=%d body=%q want 200/%q", code, body, testZipBody)
	}

	// The local-disk-cache key for the UNESCAPED module path (ArtifactID ""):
	// goproxy/github.com/Azure/azure-sdk-for-go/v1.0.0.bin
	corruptPath := filepath.Join(dir, "goproxy", "github.com", "Azure", "azure-sdk-for-go", "v1.0.0.bin")
	if _, err := os.Stat(corruptPath); err != nil {
		t.Fatalf("cache file not written at %s: %v", corruptPath, err)
	}
	if err := os.WriteFile(corruptPath, []byte("CORRUPT-TAMPER"), 0o600); err != nil {
		t.Fatalf("corrupt cache file: %v", err)
	}

	// Second (trusted) fetch: the cache serves the tampered bytes, verifyOrEvict
	// detects the sha256 mismatch, evicts, refetches from upstream and reverifies.
	if code, _, body := get(t, goproxyZipURL(srv.URL)); code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("second fetch: code=%d body=%q want 200/%q (evict+refetch+reverify)", code, body, testZipBody)
	}
	if got := atomic.LoadInt32(&zipCalls); got < 2 {
		t.Errorf("zip fetches = %d want >= 2 (initial + refetch)", got)
	}
	if b, err := os.ReadFile(corruptPath); err == nil && string(b) == "CORRUPT-TAMPER" { //nolint:gosec // G304: path under t.TempDir()
		t.Error("cache file still contains the tampered bytes after evict+refetch")
	}
}

func TestGoproxyE2EPersistentMismatch502(t *testing.T) {
	up, _ := newUpstream(t)
	store := newMemStore()
	store.recs[k(testModule, testVersion)] = Record{ModulePath: testModule, Version: testVersion, ValidationHash: "deadbeef", ValidatedAt: time.Now().UTC()}
	srv := newTestServer(t, newE2EAdapter(t, "/goproxy", up.URL, store, t.TempDir(), nil))

	code, _, body := get(t, goproxyZipURL(srv.URL))
	if code != http.StatusBadGateway {
		t.Fatalf("code=%d want 502 (integrity mismatch)", code)
	}
	if !strings.Contains(string(body), "integrity mismatch") {
		t.Errorf("body = %q", body)
	}
}

// --- e2e: validation gates ---

func TestGoproxyE2EMinPublicationAgeRejectsRecent(t *testing.T) {
	up, _ := newUpstreamAt(t, time.Now().UTC())
	a := newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), []config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 3650")},
	})
	srv := newTestServer(t, a)

	code, _, body := get(t, goproxyZipURL(srv.URL))
	if code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (recent publication rejected)", code)
	}
	if !strings.Contains(string(body), "min-publication-age") {
		t.Errorf("body = %q", body)
	}
}

func TestGoproxyE2ECveCheckDenyRejectsKnownVuln(t *testing.T) {
	osv := osvHitServer(t)
	up, _ := newUpstream(t)
	a := newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), []config.Middleware{
		{Type: "cve-check", Params: yamlNode("endpoint: " + osv.URL + "\nmode: deny")},
	})
	srv := newTestServer(t, a)

	code, _, body := get(t, goproxyZipURL(srv.URL))
	if code != http.StatusForbidden {
		t.Fatalf("code=%d want 403 (known vuln denied)", code)
	}
	if !strings.Contains(string(body), "cve-check") {
		t.Errorf("body = %q", body)
	}
}

// --- e2e: project-scoped dependency tracking ---

func TestGoproxyE2EProjectScopedTrackingFakeTracker(t *testing.T) {
	up, _ := newUpstream(t)
	tracker := &fakeDependencyTracker{}
	a := newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), nil)
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

func TestGoproxyE2EDefaultPathNotTracked(t *testing.T) {
	up, _ := newUpstream(t)
	tracker := &fakeDependencyTracker{}
	a := newE2EAdapter(t, "/goproxy", up.URL, newMemStore(), t.TempDir(), nil)
	a.tracker = tracker
	srv := newTestServer(t, a)

	code, _, body := get(t, goproxyZipURL(srv.URL))
	if code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("code=%d body=%q want 200/%q", code, body, testZipBody)
	}
	if recs := tracker.all(); len(recs) != 0 {
		t.Fatalf("tracked %d records on the default path, want 0", len(recs))
	}
}

// TestGoproxyE2EProjectScopedTrackingPostgres is the config-driven Factory proof:
// the goproxy registry block loads through goproxy.Factory (server.New), the
// OpenStorage schema applies, the real tracker persists a DependencyRecord, and
// the project-scoped route serves + tracks end-to-end.
func TestGoproxyE2EProjectScopedTrackingPostgres(t *testing.T) {
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping goproxy postgres e2e")
	}

	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = d.Close() }()

	up, _ := newUpstream(t)
	cacheDir := t.TempDir()
	cfg := &config.Config{
		Auth:    config.Auth{Token: "tok", AdminToken: "admintok"},
		Storage: config.Storage{Type: "postgres", DSN: dsn},
		Log:     config.Log{Level: "warn", Format: "json"},
		Registries: []config.RegistryConfig{
			{Type: "goproxy", Prefix: "/goproxy", Upstream: up.URL,
				Validation: []config.Middleware{
					{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
				},
				Retrieval: []config.Middleware{
					{Type: "local-disk-cache", Params: yamlNode("path: " + filepath.Join(cacheDir, "goproxy"))},
					{Type: "upstream-registry"},
				}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	srv, err := server.New(ctx, cfg, d)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// server.New applied the goproxy + projects + project_dependencies schemas;
	// clean for an isolated run.
	for _, tbl := range []string{"goproxy_validated_modules", "project_dependencies", "projects"} {
		if _, err := d.ExecContext(ctx, "DELETE FROM "+tbl); err != nil { //nolint:gosec // G202: fixed internal constant
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	// Create project acme with no registry overrides (empty registries map), so it
	// falls back to the global goproxy pipelines (min-publication-age min_days 0).
	if code, respBody := authedDo(t, httpSrv.URL, http.MethodPost, "/admin/projects", `{"key":"acme","registries":{}}`, "admintok"); code != http.StatusCreated {
		t.Fatalf("create project: code=%d want 201, body=%s", code, respBody)
	}

	// Install through the project-scoped route: real Factory, real goproxy storage,
	// real tracker.
	status, body := authedGet(t, httpSrv.URL, "/goproxy/p/acme/"+testModuleEscaped+"/@v/"+testVersion+".zip", "tok")
	if status != http.StatusOK || body != testZipBody {
		t.Fatalf("install: code=%d body=%q want 200/%q", status, body, testZipBody)
	}

	// The tracker flushes asynchronously (5s interval); poll the DB until the
	// dependency row appears (mirrors the async-flush polling in
	// TestAdminE2EDependencies).
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte(testZipBody)))
	deadline := time.Now().Add(10 * time.Second)
	for {
		var registry, pkg, version, artifactID, sha string
		err := d.QueryRowContext(ctx, `
			SELECT registry, pkg, version, artifact_id, sha256
			FROM project_dependencies WHERE project_key='acme'`).
			Scan(&registry, &pkg, &version, &artifactID, &sha)
		if err == nil {
			if registry != "goproxy" || pkg != testModule || version != testVersion ||
				artifactID != "" || sha != wantHash {
				t.Fatalf("dependency row = registry=%q pkg=%q version=%q artifact_id=%q sha256=%q", registry, pkg, version, artifactID, sha)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dependency row never appeared within 10s; last err=%v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
