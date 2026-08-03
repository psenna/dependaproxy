package pypi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// osvControl is a controllable fake OSV endpoint: the served vuln list can be
// flipped mid-test, and hits are counted.
type osvControl struct {
	hits  atomic.Int64
	vulns atomic.Value // []cveosv.Vuln
}

// newOSV starts the fake OSV server with an initially-clean advisory list.
func newOSV(t *testing.T) (*httptest.Server, *osvControl) {
	t.Helper()
	ctrl := &osvControl{}
	ctrl.vulns.Store([]cveosv.Vuln{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctrl.hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req cveosv.QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(cveosv.QueryResponse{Vulns: ctrl.vulns.Load().([]cveosv.Vuln)})
	}))
	t.Cleanup(srv.Close)
	return srv, ctrl
}

// newCveRetrievalAdapter builds the pypi adapter with a retrieval chain of
// cve-check-retrieval (FIRST) -> local-disk-cache -> upstream-registry and a
// validation chain of min-publication-age ONLY (no validation cve-check), so a
// deny on request 2 must come from the retrieval stage. mode selects the
// cve-check-retrieval mode; now is the injected clock for deterministic TTL
// expiry.
func newCveRetrievalAdapter(t *testing.T, osvURL, mode string, client RegistryClient, store Store, now func() time.Time) *pypiAdapter {
	t.Helper()
	dir := t.TempDir()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: pyYamlNode("min_days: 0")}, // age gate off; retrieval cve-check gates
	})
	if err != nil {
		t.Fatal(err)
	}
	// Build the retrieval chain manually (tail-first) so the cve-check-retrieval
	// middleware gets an injectable clock for deterministic TTL expiry.
	upstream := NewUpstream(client)
	lc := localcache.New(dir, upstream)
	head := cverecheck.New(cveosv.Params{Endpoint: osvURL, Mode: mode, CacheTTL: time.Hour}, nil, lc, now)
	retrieval := pipeline.RetrievalPipeline{Head: head}

	mp, err := reg.BuildMutation(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: lc}
	resolver := project.NewResolver("pypi", reg, fakeProjectStore{}, global)
	return &pypiAdapter{
		prefix:   "/pypi",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// TestCveRetrievalDeniesStoredFileAfterAdvisory proves the retrieval stage
// re-checks OSV on a serve from storage: a file stored while OSV was clean is
// denied on the next serve once an advisory appears (with no validation
// cve-check configured, so only the retrieval stage can deny).
func TestCveRetrievalDeniesStoredFileAfterAdvisory(t *testing.T) {
	osv, ctrl := newOSV(t)
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := newCveRetrievalAdapter(t, osv.URL, "deny", c, store, func() time.Time { return now })
	srv := newTestServer(t, a)

	// Request 1 (untrusted): OSV is clean -> stored and served 200.
	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("request 1: code=%d body=%q want 200/WHEEL", code, body)
	}
	if len(store.recs) != 1 {
		t.Fatalf("request 1 should store the validated file, got %d records", len(store.recs))
	}
	if ctrl.hits.Load() != 1 {
		t.Fatalf("request 1 should query OSV once, got %d hits", ctrl.hits.Load())
	}

	// An advisory is published for this version.
	ctrl.vulns.Store([]cveosv.Vuln{{ID: "CVE-2026-9999", Summary: "retroactive advisory"}})
	// Advance past the 1h OSV cache_ttl so request 2 re-queries OSV.
	now = now.Add(2 * time.Hour)

	// Request 2 (trusted, from storage): the retrieval stage re-checks OSV and
	// denies -> 403 with the vuln IDs surfaced in the body.
	before := ctrl.hits.Load()
	code, body = fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != http.StatusForbidden {
		t.Fatalf("request 2: code=%d want 403 (retrieval-stage deny)", code)
	}
	if !strings.Contains(string(body), "CVE-2026-9999") {
		t.Fatalf("request 2: 403 body should surface the vuln ID, got %q", body)
	}
	if !strings.Contains(string(body), "testpkg@1.0.0") {
		t.Fatalf("request 2: 403 body should name package@version, got %q", body)
	}
	if delta := ctrl.hits.Load() - before; delta != 1 {
		t.Fatalf("request 2 should re-query OSV exactly once (after TTL expiry), got %d hits", delta)
	}
}

// TestCveRetrievalWarnServesStoredFile proves mode warn serves the stored file
// while still re-querying OSV.
func TestCveRetrievalWarnServesStoredFile(t *testing.T) {
	osv, ctrl := newOSV(t)
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := newCveRetrievalAdapter(t, osv.URL, "warn", c, store, func() time.Time { return now })
	srv := newTestServer(t, a)

	if code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg"); code != 200 || string(body) != "WHEEL" {
		t.Fatalf("request 1: code=%d body=%q want 200/WHEEL", code, body)
	}

	ctrl.vulns.Store([]cveosv.Vuln{{ID: "CVE-2026-9999", Summary: "retroactive advisory"}})
	now = now.Add(2 * time.Hour)

	before := ctrl.hits.Load()
	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "WHEEL" {
		t.Fatalf("request 2 (warn): code=%d body=%q want 200/WHEEL", code, body)
	}
	if delta := ctrl.hits.Load() - before; delta != 1 {
		t.Fatalf("request 2 (warn) should re-query OSV exactly once, got %d hits", delta)
	}
}
