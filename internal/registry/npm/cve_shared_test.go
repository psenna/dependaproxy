package npm

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cvecheckcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/storage/db"
)

// countingOSV is a fake OSV endpoint returning the given vuln list for any
// query and counting how many times it is hit.
func countingOSV(t *testing.T, vulns []cveosv.Vuln) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req cveosv.QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(cveosv.QueryResponse{Vulns: vulns})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// countingOSVRaw is a fake OSV endpoint returning the given raw vuln maps (so
// tests can exercise database_specific.severity) for any query and counting how
// many times it is hit.
func countingOSVRaw(t *testing.T, raws []map[string]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req cveosv.QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": raws})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// newSharedCveAdapter builds the npm adapter with BOTH the validation cve-check
// and the retrieval cve-check-retrieval middlewares sharing one cveosv.Client
// (mirroring the adapter Factory), so a single request that runs both stages
// must query OSV exactly once. valMode/retMode select each middleware's mode;
// minSeverity sets the shared client's min_severity threshold ("" = unset).
func newSharedCveAdapter(t *testing.T, osvURL, valMode, retMode, minSeverity string, client RegistryClient, store Store) *npmAdapter {
	t.Helper()
	dir := t.TempDir()
	shared := cveosv.NewClient(cveosv.Params{Endpoint: osvURL, CacheTTL: time.Hour, MinSeverity: minSeverity}, nil, func() time.Time { return time.Now().UTC() })

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.FactoryWithClient(shared))
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.FactoryWithClient(shared))
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")}, // age gate off; only cve-check gates
		{Type: "cve-check", Params: yamlNode("mode: " + valMode)},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "cve-check-retrieval", Params: yamlNode("mode: " + retMode)},
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

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp}
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		global.Cache = e
	}
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	return &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// TestCveSharedClientDeniesVulnerableOnce proves the shared client/cache on the
// deny path: with the retrieval stage in warn mode (so it serves and populates
// the shared cache) and the validation stage in deny mode, a vulnerable version
// is denied once with a single OSV round-trip — the validation stage reads the
// result the retrieval stage cached.
func TestCveSharedClientDeniesVulnerableOnce(t *testing.T) {
	osv, hits := countingOSV(t, []cveosv.Vuln{{ID: "CVE-2026-0001", Summary: "arbitrary code execution"}})
	store := newMemStore()
	pack, raw := buildPack(time.Now().Add(-30*24*time.Hour), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newSharedCveAdapter(t, osv.URL, "deny", "warn", "", client, store)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != http.StatusForbidden {
		t.Fatalf("vulnerable version should be denied with 403, got %d", code)
	}
	if hits.Load() != 1 {
		t.Fatalf("shared client should query OSV exactly once, got %d hits", hits.Load())
	}
}

// TestCveSharedClientCleanServesOnce proves the shared cache on the serve path:
// with a clean OSV, the retrieval stage queries OSV (populating the shared
// cache) and the validation stage reads the cached result, so the request serves
// 200 with a single OSV round-trip.
func TestCveSharedClientCleanServesOnce(t *testing.T) {
	osv, hits := countingOSV(t, nil)
	store := newMemStore()
	pack, raw := buildPack(time.Now().Add(-30*24*time.Hour), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newSharedCveAdapter(t, osv.URL, "deny", "deny", "", client, store)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("clean version should serve 200/TARBALL, got code=%d body=%q", code, body)
	}
	if hits.Load() != 1 {
		t.Fatalf("shared cache should serve the validation stage: expected 1 OSV hit, got %d", hits.Load())
	}
}

// newCveCacheAdapter builds the npm adapter with the retrieval
// cve-check-retrieval middleware wired to a persistent cvecheckcache.Store
// (mirroring the adapter Factory when cache_enabled is set), so a serve can be
// answered from the DB cache without an OSV round-trip.
func newCveCacheAdapter(t *testing.T, osvURL string, cache cvecheckcache.Store, cacheDuration time.Duration, client RegistryClient, store Store) *npmAdapter {
	t.Helper()
	dir := t.TempDir()
	shared := cveosv.NewClient(cveosv.Params{Endpoint: osvURL, CacheTTL: time.Hour}, nil, func() time.Time { return time.Now().UTC() })

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.FactoryWithClientAndCache(shared, cache, cacheDuration, func() time.Time { return time.Now().UTC() }))
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")}, // age gate off; only cve-check-retrieval gates
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "cve-check-retrieval", Params: yamlNode("mode: deny")},
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

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp}
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		global.Cache = e
	}
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	return &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// TestCveRetrievalCacheSurvivesRestart proves the persistent Postgres cache
// serves a second adapter instance (a "restart" with a fresh in-memory cache)
// from the DB: the first serve queries OSV once and stores severity-band counts;
// the second serve is denied from the DB cache with zero OSV round-trips.
func TestCveRetrievalCacheSurvivesRestart(t *testing.T) {
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping cve cache postgres test")
	}
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	osv, hits := countingOSV(t, []cveosv.Vuln{{ID: "CVE-2026-0001", Summary: "arbitrary code execution"}})
	store := newMemStore()
	pack, raw := buildPack(time.Now().Add(-30*24*time.Hour), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}

	// OpenStore applies the (idempotent) cache schema — clean AFTER it, not
	// before, so the DELETE does not fail with "relation does not exist" when
	// this test is the first to touch the table on a fresh database (test
	// package ordering under `go test -p 1 ./...` decides that).
	cache, err := cvecheckcache.OpenStore(ctx, d)
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM middleware_retrieval_cvecheck_cache`); err != nil {
		t.Fatalf("clean cache: %v", err)
	}

	// First "instance": cache miss → OSV query → counts stored in Postgres.
	a1 := newCveCacheAdapter(t, osv.URL, cache, 7*24*time.Hour, client, store)
	srv1 := newTestServer(t, a1)
	code, _ := fetchViaProxy(t, srv1.URL+"/npm", "testpkg", "1.0.0")
	if code != http.StatusForbidden {
		t.Fatalf("request 1 should be denied (vulnerable), got %d", code)
	}
	if hits.Load() != 1 {
		t.Fatalf("request 1 should query OSV once, got %d hits", hits.Load())
	}

	// "Restart": a fresh adapter instance (fresh in-memory cache) over the same
	// DB. The second serve must be denied from the DB cache with zero OSV hits.
	a2 := newCveCacheAdapter(t, osv.URL, cache, 7*24*time.Hour, client, store)
	srv2 := newTestServer(t, a2)
	code2, _ := fetchViaProxy(t, srv2.URL+"/npm", "testpkg", "1.0.0")
	if code2 != http.StatusForbidden {
		t.Fatalf("request 2 should be denied from the DB cache, got %d", code2)
	}
	if hits.Load() != 1 {
		t.Fatalf("request 2 should be served from the DB cache: expected 1 total OSV hit, got %d", hits.Load())
	}
}

// TestCveSharedClientRespectsThreshold proves the shared client's min_severity
// threshold gates both stages end-to-end: a low-severity advisory below the
// threshold is filtered out (served), while a high-severity advisory at/above
// the threshold is denied.
func TestCveSharedClientRespectsThreshold(t *testing.T) {
	// A low-severity advisory below the min_severity: high threshold is filtered
	// out, so the package is served.
	osvLow, hitsLow := countingOSVRaw(t, []map[string]any{
		{"id": "CVE-2026-0001", "database_specific": map[string]any{"severity": "LOW"}},
	})
	store := newMemStore()
	pack, raw := buildPack(time.Now().Add(-30*24*time.Hour), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newSharedCveAdapter(t, osvLow.URL, "deny", "warn", "high", client, store)
	srv := newTestServer(t, a)
	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "TARBALL" {
		t.Fatalf("low-severity vuln below threshold should serve, got code=%d body=%q", code, body)
	}
	if hitsLow.Load() != 1 {
		t.Fatalf("expected 1 OSV hit, got %d", hitsLow.Load())
	}

	// A high-severity advisory at/above the threshold is denied.
	osvHigh, hitsHigh := countingOSVRaw(t, []map[string]any{
		{"id": "CVE-2026-0002", "database_specific": map[string]any{"severity": "HIGH"}},
	})
	store2 := newMemStore()
	client2 := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a2 := newSharedCveAdapter(t, osvHigh.URL, "deny", "warn", "high", client2, store2)
	srv2 := newTestServer(t, a2)
	code2, _ := fetchViaProxy(t, srv2.URL+"/npm", "testpkg", "1.0.0")
	if code2 != http.StatusForbidden {
		t.Fatalf("high-severity vuln at/above threshold should be denied, got %d", code2)
	}
	if hitsHigh.Load() != 1 {
		t.Fatalf("expected 1 OSV hit, got %d", hitsHigh.Load())
	}
}
