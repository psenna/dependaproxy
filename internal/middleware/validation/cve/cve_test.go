package cve

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
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func testCtx(pkg, version string) *pipeline.PipelineContext {
	return pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", pkg, version, "")
}

// osvServer spins up a fake OSV endpoint returning the given vuln IDs for any
// query, and counts how many times it is hit.
func osvServer(t *testing.T, ids []string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		vulns := []osvVuln{}
		for _, id := range ids {
			vulns = append(vulns, osvVuln{ID: id, Summary: "test summary"})
		}
		_ = json.NewEncoder(w).Encode(osvQueryResponse{Vulns: vulns})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// osvServerRaw spins up a fake OSV endpoint returning the given raw vuln maps
// (so tests can exercise database_specific.severity) for any query, and counts
// how many times it is hit.
func osvServerRaw(t *testing.T, raws []map[string]any) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": raws})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestDenyRejectsVulnerable(t *testing.T) {
	srv, _ := osvServer(t, []string{"CVE-2021-1234", "GHSA-abc"})
	m := New(params{Endpoint: srv.URL}, nil, func() time.Time { return time.Now().UTC() })
	err := m.Validate(testCtx("lodash", "4.17.20"))
	if err == nil {
		t.Fatal("expected rejection for a vulnerable version")
	}
	if !strings.Contains(err.Error(), "CVE-2021-1234") || !strings.Contains(err.Error(), "GHSA-abc") {
		t.Fatalf("error should list the vuln IDs, got: %v", err)
	}
	if !strings.Contains(err.Error(), "lodash@4.17.20") {
		t.Fatalf("error should name package@version, got: %v", err)
	}
	if errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("a real deny verdict must not be flagged transient, got: %v", err)
	}
}

func TestWarnAllowsVulnerable(t *testing.T) {
	srv, _ := osvServer(t, []string{"CVE-2021-1234"})
	m := New(params{Endpoint: srv.URL, Mode: "warn"}, nil, func() time.Time { return time.Now().UTC() })
	ctx := testCtx("lodash", "4.17.20")
	if err := m.Validate(ctx); err != nil {
		t.Fatalf("warn mode should accept a vulnerable version, got %v", err)
	}
	got, ok := ctx.Metadata["cve"].([]string)
	if !ok || len(got) != 1 || got[0] != "CVE-2021-1234" {
		t.Fatalf("warn mode should record the CVE IDs in metadata, got %#v", ctx.Metadata["cve"])
	}
}

func TestCleanPasses(t *testing.T) {
	srv, _ := osvServer(t, nil)
	m := New(params{Endpoint: srv.URL}, nil, func() time.Time { return time.Now().UTC() })
	if err := m.Validate(testCtx("lodash", "4.17.21")); err != nil {
		t.Fatalf("a clean version should pass, got %v", err)
	}
}

func TestFailOpenOnSourceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	m := New(params{Endpoint: srv.URL}, nil, nil) // default on_error = fail_open
	if err := m.Validate(testCtx("lodash", "4.17.20")); err != nil {
		t.Fatalf("fail_open should accept when the source errors, got %v", err)
	}
}

func TestFailClosedOnSourceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	m := New(params{Endpoint: srv.URL, OnError: "fail_closed"}, nil, nil)
	err := m.Validate(testCtx("lodash", "4.17.20"))
	if err == nil {
		t.Fatal("fail_closed should reject when the source errors")
	}
	if !strings.Contains(err.Error(), "cve-check:") {
		t.Fatalf("error should be prefixed with cve-check:, got: %v", err)
	}
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("fail_closed on a source error should be flagged transient, got: %v", err)
	}
}

func TestFailClosedOnNetworkError(t *testing.T) {
	m := New(params{Endpoint: "http://127.0.0.1:1", OnError: "fail_closed"}, &http.Client{Timeout: time.Second}, nil)
	err := m.Validate(testCtx("lodash", "4.17.20"))
	if err == nil {
		t.Fatal("fail_closed should reject on a network error")
	}
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("fail_closed on a network error should be flagged transient, got: %v", err)
	}
}

func TestUnknownRegistrySkipped(t *testing.T) {
	srv, hits := osvServer(t, []string{"CVE-2021-1234"})
	m := New(params{Endpoint: srv.URL}, nil, nil)
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "maven", "g:a", "1.0", "")
	if err := m.Validate(ctx); err != nil {
		t.Fatalf("a registry OSV does not cover should pass, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("should not query OSV for an unknown ecosystem, got %d hits", hits.Load())
	}
}

func TestCacheAvoidsRepeatedQueries(t *testing.T) {
	srv, hits := osvServer(t, []string{"CVE-2021-1234"})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := New(params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if err := m.Validate(testCtx("lodash", "4.17.20")); err == nil {
			t.Fatalf("iteration %d should still be denied", i)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("within TTL the result should be cached: expected 1 OSV query, got %d", hits.Load())
	}
}

func TestCacheExpires(t *testing.T) {
	srv, hits := osvServer(t, []string{"CVE-2021-1234"})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := New(params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, func() time.Time { return now })
	_ = m.Validate(testCtx("lodash", "4.17.20"))
	now = now.Add(2 * time.Hour)
	_ = m.Validate(testCtx("lodash", "4.17.20"))
	if hits.Load() != 2 {
		t.Fatalf("after TTL expiry a fresh query is expected: got %d hits", hits.Load())
	}
}

// TestFactoryWithClientSharesCache proves FactoryWithClient builds middlewares
// that share the passed client and its cache: two middlewares built with
// DIFFERENT mode/on_error params still share the same client/cache pointers,
// and a query through the first populates the cache so the second does not hit
// OSV again.
func TestFactoryWithClientSharesCache(t *testing.T) {
	srv, hits := osvServer(t, []string{"CVE-2021-1234"})
	shared := cveosv.NewClient(params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, func() time.Time { return time.Now().UTC() })

	var n1 yaml.Node
	if err := n1.Encode(map[string]any{"mode": "warn"}); err != nil {
		t.Fatal(err)
	}
	var n2 yaml.Node
	if err := n2.Encode(map[string]any{"mode": "deny"}); err != nil {
		t.Fatal(err)
	}
	mw1, err := FactoryWithClient(shared)(n1)
	if err != nil {
		t.Fatalf("factory 1: %v", err)
	}
	mw2, err := FactoryWithClient(shared)(n2)
	if err != nil {
		t.Fatalf("factory 2: %v", err)
	}
	m1 := mw1.(*Middleware)
	m2 := mw2.(*Middleware)
	if m1.client != shared || m2.client != shared {
		t.Fatal("both middlewares must share the same client pointer")
	}
	if m1.cache != shared.Cache() || m2.cache != shared.Cache() {
		t.Fatal("both middlewares must share the same cache pointer")
	}
	if m1.mode == m2.mode {
		t.Fatalf("modes should differ per middleware, got %q == %q", m1.mode, m2.mode)
	}
	// Query through the first middleware populates the shared cache; the second
	// must not hit OSV again.
	if err := m1.Validate(testCtx("lodash", "4.17.20")); err != nil {
		t.Fatalf("warn-mode validate should pass, got %v", err)
	}
	if err := m2.Validate(testCtx("lodash", "4.17.20")); err == nil {
		t.Fatal("deny-mode validate should reject the vulnerable version")
	}
	if hits.Load() != 1 {
		t.Fatalf("shared cache should serve the second query: expected 1 OSV hit, got %d", hits.Load())
	}
}

func TestFactoryDecodesParams(t *testing.T) {
	var n yaml.Node
	if err := n.Encode(map[string]any{"mode": "warn", "endpoint": "http://example.com"}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(n)
	if err != nil {
		t.Fatalf("factory should decode valid params: %v", err)
	}
	m := mw.(*Middleware)
	if m.mode != "warn" || m.endpoint != "http://example.com" {
		t.Fatalf("unexpected decoded params: mode=%q endpoint=%q", m.mode, m.endpoint)
	}
	if m.client.HTTPClient().Timeout != defaultTimeout {
		t.Fatalf("timeout should default, got %v", m.client.HTTPClient().Timeout)
	}
	if m.cache.TTL != defaultCacheTTL {
		t.Fatalf("cache_ttl should default, got %v", m.cache.TTL)
	}
}

func TestDenyRespectsMinSeverity(t *testing.T) {
	// A low-severity advisory below the min_severity: high threshold is filtered
	// out, so the version passes.
	srv, _ := osvServerRaw(t, []map[string]any{
		{"id": "CVE-2021-1234", "database_specific": map[string]any{"severity": "LOW"}},
	})
	m := New(params{Endpoint: srv.URL, MinSeverity: "high"}, nil, func() time.Time { return time.Now().UTC() })
	if err := m.Validate(testCtx("lodash", "4.17.20")); err != nil {
		t.Fatalf("low-severity vuln below threshold should pass, got %v", err)
	}

	// A high-severity advisory at/above the threshold is denied.
	srv2, _ := osvServerRaw(t, []map[string]any{
		{"id": "CVE-2021-1234", "database_specific": map[string]any{"severity": "HIGH"}},
	})
	m2 := New(params{Endpoint: srv2.URL, MinSeverity: "high"}, nil, func() time.Time { return time.Now().UTC() })
	err := m2.Validate(testCtx("lodash", "4.17.20"))
	if err == nil {
		t.Fatal("high-severity vuln at/above threshold should be denied")
	}
	if !strings.Contains(err.Error(), "CVE-2021-1234[high]") {
		t.Fatalf("deny message should render ID[band], got: %v", err)
	}
}

func TestWarnRespectsMinSeverity(t *testing.T) {
	srv, _ := osvServerRaw(t, []map[string]any{
		{"id": "CVE-LOW", "database_specific": map[string]any{"severity": "LOW"}},
		{"id": "CVE-HIGH", "database_specific": map[string]any{"severity": "HIGH"}},
	})
	m := New(params{Endpoint: srv.URL, Mode: "warn", MinSeverity: "high"}, nil, func() time.Time { return time.Now().UTC() })
	ctx := testCtx("lodash", "4.17.20")
	if err := m.Validate(ctx); err != nil {
		t.Fatalf("warn mode should accept, got %v", err)
	}
	got, ok := ctx.Metadata["cve"].([]string)
	if !ok || len(got) != 1 || got[0] != "CVE-HIGH[high]" {
		t.Fatalf("warn mode should record only at/above-threshold vulns with bands, got %#v", ctx.Metadata["cve"])
	}
}

// TestUnsetThresholdBareIDs locks in the byte-for-byte backward-compat
// guarantee: with min_severity unset and real severity data present (a CVSS
// vector that resolves to a known band), the deny message and warn metadata
// must render bare IDs (no "[band]" suffix), identical to the pre-min_severity
// behavior.
func TestUnsetThresholdBareIDs(t *testing.T) {
	raw := []map[string]any{
		{"id": "CVE-2021-1234", "summary": "arbitrary code execution",
			"severity": []map[string]any{{"type": "CVSS_V3", "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
	}
	// deny: the error message lists the bare ID, no [critical] suffix.
	srv, _ := osvServerRaw(t, raw)
	m := New(params{Endpoint: srv.URL}, nil, func() time.Time { return time.Now().UTC() })
	err := m.Validate(testCtx("lodash", "4.17.20"))
	if err == nil {
		t.Fatal("vulnerable version should be denied")
	}
	if strings.Contains(err.Error(), "CVE-2021-1234[") {
		t.Fatalf("unset threshold should render bare IDs, got: %v", err)
	}
	if !strings.Contains(err.Error(), "CVE-2021-1234") {
		t.Fatalf("deny message should list the vuln ID, got: %v", err)
	}

	// warn: metadata records the bare ID, no [critical] suffix.
	srv2, _ := osvServerRaw(t, raw)
	m2 := New(params{Endpoint: srv2.URL, Mode: "warn"}, nil, func() time.Time { return time.Now().UTC() })
	ctx := testCtx("lodash", "4.17.20")
	if err := m2.Validate(ctx); err != nil {
		t.Fatalf("warn mode should accept, got %v", err)
	}
	got, ok := ctx.Metadata["cve"].([]string)
	if !ok || len(got) != 1 || got[0] != "CVE-2021-1234" {
		t.Fatalf("unset threshold should record bare ID in metadata, got %#v", ctx.Metadata["cve"])
	}
}
