package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	if err := m.Validate(testCtx("lodash", "4.17.20")); err == nil {
		t.Fatal("fail_closed should reject when the source errors")
	}
}

func TestFailClosedOnNetworkError(t *testing.T) {
	m := New(params{Endpoint: "http://127.0.0.1:1", OnError: "fail_closed"}, &http.Client{Timeout: time.Second}, nil)
	if err := m.Validate(testCtx("lodash", "4.17.20")); err == nil {
		t.Fatal("fail_closed should reject on a network error")
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
	if m.client.Timeout != defaultTimeout {
		t.Fatalf("timeout should default, got %v", m.client.Timeout)
	}
	if m.cache.ttl != defaultCacheTTL {
		t.Fatalf("cache_ttl should default, got %v", m.cache.ttl)
	}
}

func TestCacheBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newTTLCache(time.Hour, 4, func() time.Time { return now })
	for i := 0; i < 10; i++ {
		c.put(fmt.Sprintf("k%d", i), []osvVuln{{ID: fmt.Sprintf("CVE-%d", i)}})
	}
	retrievable := 0
	for i := 0; i < 10; i++ {
		if _, ok := c.get(fmt.Sprintf("k%d", i)); ok {
			retrievable++
		}
	}
	if retrievable > 4 {
		t.Fatalf("cache should hold at most max entries, got %d retrievable", retrievable)
	}
}

func TestCachePurgesExpiredOnPut(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := newTTLCache(time.Hour, 4, func() time.Time { return now })
	c.put("k0", []osvVuln{{ID: "CVE-1"}})
	now = now.Add(2 * time.Hour) // k0 now expired
	c.put("k1", []osvVuln{{ID: "CVE-2"}}) // triggers a purge
	if _, ok := c.get("k0"); ok {
		t.Fatal("expired entry should have been purged on put")
	}
	if _, ok := c.get("k1"); !ok {
		t.Fatal("fresh entry should be present")
	}
}
