package cverecheck

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// fakeNext is a retrieval middleware stub that optionally sets ctx.Tarball and
// counts calls.
type fakeNext struct {
	calls int32
	hit   bool
	err   error
	data  []byte
}

func (n *fakeNext) Name() string { return "fake-next" }
func (n *fakeNext) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	atomic.AddInt32(&n.calls, 1)
	if n.err != nil {
		return false, n.err
	}
	if !n.hit {
		return false, nil
	}
	ctx.Tarball = &pipeline.Tarball{Bytes: n.data}
	return true, nil
}

// osvServer spins up a fake OSV endpoint returning the given vulns for any
// query and counts hits.
func osvServer(t *testing.T, vulns []cveosv.Vuln) (*httptest.Server, *atomic.Int64) {
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

// osv500Server always returns 500 on /v1/query.
func osv500Server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testCtx(registry, pkg, version string) *pipeline.PipelineContext {
	return pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), registry, pkg, version, "")
}

func fixedNow() func() time.Time {
	return func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
}

func TestCleanServesBytes(t *testing.T) {
	srv, _ := osvServer(t, nil)
	next := &fakeNext{hit: true, data: []byte("BYTES")}
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, next, fixedNow())
	ctx := testCtx("npm", "lodash", "4.17.20")
	hit, err := m.Fetch(ctx)
	if err != nil {
		t.Fatalf("clean should serve, got %v", err)
	}
	if !hit {
		t.Fatal("clean should be a hit")
	}
	if ctx.Tarball == nil || string(ctx.Tarball.Bytes) != "BYTES" {
		t.Fatalf("tarball bytes not preserved: %v", ctx.Tarball)
	}
}

func TestDenyRejectsWithErrRejected(t *testing.T) {
	srv, _ := osvServer(t, []cveosv.Vuln{{ID: "CVE-2026-9999", Summary: "bad"}, {ID: "GHSA-x"}})
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	hit, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
	if err == nil {
		t.Fatal("deny should reject")
	}
	if hit {
		t.Fatal("deny should not be a hit")
	}
	if !errors.Is(err, pipeline.ErrRejected) {
		t.Fatalf("err should wrap ErrRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "lodash@4.17.20") {
		t.Fatalf("message should name package@version, got: %v", err)
	}
	if !strings.Contains(err.Error(), "CVE-2026-9999") || !strings.Contains(err.Error(), "GHSA-x") {
		t.Fatalf("message should list vuln IDs, got: %v", err)
	}
}

func TestWarnServesAndAnnotates(t *testing.T) {
	srv, _ := osvServer(t, []cveosv.Vuln{{ID: "CVE-2026-9999", Summary: "bad"}})
	next := &fakeNext{hit: true, data: []byte("BYTES")}
	m := New(cveosv.Params{Endpoint: srv.URL, Mode: "warn"}, nil, next, fixedNow())
	ctx := testCtx("npm", "lodash", "4.17.20")
	hit, err := m.Fetch(ctx)
	if err != nil {
		t.Fatalf("warn should serve, got %v", err)
	}
	if !hit {
		t.Fatal("warn should be a hit")
	}
	got, ok := ctx.Metadata["cve-retrieval"].([]string)
	if !ok || len(got) != 1 || got[0] != "CVE-2026-9999" {
		t.Fatalf("warn should record vuln IDs in metadata, got %#v", ctx.Metadata["cve-retrieval"])
	}
	if ctx.Tarball == nil || string(ctx.Tarball.Bytes) != "BYTES" {
		t.Fatalf("tarball bytes not preserved: %v", ctx.Tarball)
	}
}

func TestFailOpenOnOSV500(t *testing.T) {
	srv := osv500Server(t)
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	hit, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
	if err != nil {
		t.Fatalf("fail_open should serve on OSV outage, got %v", err)
	}
	if !hit {
		t.Fatal("fail_open should be a hit")
	}
}

func TestFailClosedOnOSV500(t *testing.T) {
	srv := osv500Server(t)
	m := New(cveosv.Params{Endpoint: srv.URL, OnError: "fail_closed"}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	hit, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
	if err == nil {
		t.Fatal("fail_closed should reject on OSV outage")
	}
	if hit {
		t.Fatal("fail_closed should not be a hit")
	}
	if errors.Is(err, pipeline.ErrRejected) {
		t.Fatalf("fail_closed outage is NOT an advisory; must not wrap ErrRejected, got %v", err)
	}
}

func TestFailClosedOnNetworkError(t *testing.T) {
	m := New(cveosv.Params{Endpoint: "http://127.0.0.1:1", OnError: "fail_closed"}, &http.Client{Timeout: time.Second}, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	hit, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
	if err == nil {
		t.Fatal("fail_closed should reject on a network error")
	}
	if hit {
		t.Fatal("fail_closed should not be a hit")
	}
}

func TestCacheAvoidsRepeatedOSV(t *testing.T) {
	srv, hits := osvServer(t, []cveosv.Vuln{{ID: "CVE-2026-9999"}})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := New(cveosv.Params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		_, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
		if err == nil {
			t.Fatalf("iteration %d should still be denied", i)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("within TTL the result should be cached: expected 1 OSV query, got %d", hits.Load())
	}
}

func TestCacheExpires(t *testing.T) {
	srv, hits := osvServer(t, []cveosv.Vuln{{ID: "CVE-2026-9999"}})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := New(cveosv.Params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, func() time.Time { return now })
	if _, err := m.Fetch(testCtx("npm", "lodash", "4.17.20")); err == nil {
		t.Fatal("first fetch should be denied")
	}
	now = now.Add(2 * time.Hour)
	if _, err := m.Fetch(testCtx("npm", "lodash", "4.17.20")); err == nil {
		t.Fatal("second fetch should be denied after TTL expiry")
	}
	if hits.Load() != 2 {
		t.Fatalf("after TTL expiry a fresh query is expected: got %d hits", hits.Load())
	}
}

func TestUnknownRegistrySkipped(t *testing.T) {
	srv, hits := osvServer(t, []cveosv.Vuln{{ID: "CVE-2026-9999"}})
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	hit, err := m.Fetch(testCtx("maven", "g:a", "1.0"))
	if err != nil || !hit {
		t.Fatalf("a registry OSV does not cover should serve, got hit=%v err=%v", hit, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("should not query OSV for an unknown ecosystem, got %d hits", hits.Load())
	}
}

func TestNextErrorPropagatedUnchanged(t *testing.T) {
	srv, _ := osvServer(t, nil)
	nextErr := errors.New("upstream exploded")
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, &fakeNext{hit: true, err: nextErr}, fixedNow())
	hit, err := m.Fetch(testCtx("npm", "lodash", "4.17.20"))
	if err == nil {
		t.Fatal("next error should propagate")
	}
	if !errors.Is(err, nextErr) {
		t.Fatalf("next error should be propagated unchanged, got %v", err)
	}
	if errors.Is(err, pipeline.ErrRejected) {
		t.Fatalf("next error must not be wrapped in ErrRejected, got %v", err)
	}
	if hit {
		t.Fatal("a failed next must not be a hit")
	}
}

func TestEvictPassThrough(t *testing.T) {
	dir := t.TempDir()
	next := &fakeNext{hit: true, data: []byte("BYTES")}
	lc := localcache.New(dir, next)
	srv, _ := osvServer(t, nil)
	m := New(cveosv.Params{Endpoint: srv.URL}, nil, lc, fixedNow())

	ctx := testCtx("npm", "lodash", "4.17.20")
	if hit, err := m.Fetch(ctx); err != nil || !hit {
		t.Fatalf("first fetch: hit=%v err=%v", hit, err)
	}
	if atomic.LoadInt32(&next.calls) != 1 {
		t.Fatalf("next calls = %d want 1", next.calls)
	}

	// Evict pass-through must reach the localcache middleware and delete the
	// stored entry.
	if err := m.Evict(ctx); err != nil {
		t.Fatalf("evict: %v", err)
	}
	// A second fetch must now miss the local cache and hit upstream again.
	if hit, err := m.Fetch(ctx); err != nil || !hit {
		t.Fatalf("second fetch: hit=%v err=%v", hit, err)
	}
	if atomic.LoadInt32(&next.calls) != 2 {
		t.Fatalf("after evict, a fresh fetch should hit next again: calls=%d want 2", next.calls)
	}
}

func TestEvictNoEvictorReturnsNil(t *testing.T) {
	m := New(cveosv.Params{}, nil, &fakeNext{hit: true, data: []byte("BYTES")}, fixedNow())
	if err := m.Evict(testCtx("npm", "lodash", "4.17.20")); err != nil {
		t.Fatalf("evict without a downstream evictor should be a no-op, got %v", err)
	}
}

func TestFactoryDecodesParams(t *testing.T) {
	srv, hits := osvServer(t, nil)
	var n yaml.Node
	if err := n.Encode(map[string]any{"mode": "warn", "endpoint": srv.URL, "cache_ttl": "5m"}); err != nil {
		t.Fatal(err)
	}
	next := &fakeNext{hit: true, data: []byte("BYTES")}
	mw, err := Factory(n, next)
	if err != nil {
		t.Fatalf("factory should decode valid params: %v", err)
	}
	m := mw.(*Middleware)
	if m.mode != "warn" {
		t.Fatalf("mode = %q want warn", m.mode)
	}
	if m.client.Endpoint() != srv.URL {
		t.Fatalf("endpoint = %q want %q", m.client.Endpoint(), srv.URL)
	}
	if m.client.Cache().TTL != 5*time.Minute {
		t.Fatalf("cache_ttl = %v want 5m", m.client.Cache().TTL)
	}
	// A Factory-built middleware must still route to the passed next and use the
	// decoded endpoint (the OSV server is hit).
	ctx := testCtx("npm", "lodash", "4.17.20")
	if hit, err := m.Fetch(ctx); err != nil || !hit {
		t.Fatalf("fetch through factory-built middleware: hit=%v err=%v", hit, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("factory middleware should query the decoded endpoint, got %d hits", hits.Load())
	}
}

func TestFactoryEmptyParams(t *testing.T) {
	mw, err := Factory(yaml.Node{}, &fakeNext{hit: true, data: []byte("BYTES")})
	if err != nil {
		t.Fatalf("factory empty: %v", err)
	}
	if mw.Name() != "cve-check-retrieval" {
		t.Errorf("name = %q", mw.Name())
	}
}
