package cveosv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// osvServer spins up a fake OSV endpoint returning the given vulns for any
// query, and counts how many times it is hit.
func osvServer(t *testing.T, vulns []Vuln) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(QueryResponse{Vulns: vulns})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestEcosystem(t *testing.T) {
	for _, reg := range []string{"npm", "pypi"} {
		if eco, ok := Ecosystem(reg); !ok || eco != reg {
			t.Errorf("Ecosystem(%q) = %q,%v want %q,true", reg, eco, ok, reg)
		}
	}
	if eco, ok := Ecosystem("goproxy"); !ok || eco != "Go" {
		t.Errorf("Ecosystem(\"goproxy\") = %q,%v want \"Go\",true", eco, ok)
	}
	for _, reg := range []string{"maven", "cargo", ""} {
		if eco, ok := Ecosystem(reg); ok || eco != "" {
			t.Errorf("Ecosystem(%q) = %q,%v want \"\",false", reg, eco, ok)
		}
	}
}

func TestQueryReturnsVulns(t *testing.T) {
	srv, hits := osvServer(t, []Vuln{{ID: "CVE-2021-1234", Summary: "test summary"}, {ID: "GHSA-abc"}})
	c := NewClient(Params{Endpoint: srv.URL}, nil, func() time.Time { return time.Now().UTC() })
	vulns, err := c.Query(context.Background(), "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(vulns) != 2 || vulns[0].ID != "CVE-2021-1234" || vulns[1].ID != "GHSA-abc" {
		t.Fatalf("unexpected vulns: %+v", vulns)
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 OSV hit, got %d", hits.Load())
	}
}

func TestQueryCacheAvoidsSecondCall(t *testing.T) {
	srv, hits := osvServer(t, []Vuln{{ID: "CVE-2021-1234"}})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewClient(Params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		vulns, err := c.Query(context.Background(), "npm", "lodash", "4.17.20")
		if err != nil || len(vulns) != 1 {
			t.Fatalf("iteration %d: vulns=%v err=%v", i, vulns, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("within TTL the result should be cached: expected 1 OSV query, got %d", hits.Load())
	}
}

func TestQueryCacheExpires(t *testing.T) {
	srv, hits := osvServer(t, []Vuln{{ID: "CVE-2021-1234"}})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewClient(Params{Endpoint: srv.URL, CacheTTL: time.Hour}, nil, func() time.Time { return now })
	if _, err := c.Query(context.Background(), "npm", "lodash", "4.17.20"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := c.Query(context.Background(), "npm", "lodash", "4.17.20"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("after TTL expiry a fresh query is expected: got %d hits", hits.Load())
	}
}

func TestQueryServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(Params{Endpoint: srv.URL}, nil, nil)
	if _, err := c.Query(context.Background(), "npm", "lodash", "4.17.20"); err == nil {
		t.Fatal("expected an error on a 500 response")
	}
}

func TestQueryNetworkError(t *testing.T) {
	c := NewClient(Params{Endpoint: "http://127.0.0.1:1"}, &http.Client{Timeout: time.Second}, nil)
	if _, err := c.Query(context.Background(), "npm", "lodash", "4.17.20"); err == nil {
		t.Fatal("expected an error on a network failure")
	}
}

func TestClientDefaults(t *testing.T) {
	c := NewClient(Params{}, nil, nil)
	if c.Endpoint() != DefaultEndpoint || c.Mode() != DefaultMode || c.OnError() != DefaultOnError {
		t.Fatalf("defaults: endpoint=%q mode=%q onError=%q", c.Endpoint(), c.Mode(), c.OnError())
	}
	if c.HTTPClient().Timeout != DefaultTimeout {
		t.Fatalf("timeout should default, got %v", c.HTTPClient().Timeout)
	}
	if c.Cache().TTL != DefaultCacheTTL {
		t.Fatalf("cache_ttl should default, got %v", c.Cache().TTL)
	}
	if c.Cache().Max != DefaultCacheMax {
		t.Fatalf("cache max should default, got %d", c.Cache().Max)
	}
}

func TestCacheBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCache(time.Hour, 4, func() time.Time { return now })
	for i := 0; i < 10; i++ {
		c.Put(fmt.Sprintf("k%d", i), []Vuln{{ID: fmt.Sprintf("CVE-%d", i)}})
	}
	retrievable := 0
	for i := 0; i < 10; i++ {
		if _, ok := c.Get(fmt.Sprintf("k%d", i)); ok {
			retrievable++
		}
	}
	if retrievable > 4 {
		t.Fatalf("cache should hold at most max entries, got %d retrievable", retrievable)
	}
}

func TestCachePurgesExpiredOnPut(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCache(time.Hour, 4, func() time.Time { return now })
	c.Put("k0", []Vuln{{ID: "CVE-1"}})
	now = now.Add(2 * time.Hour)       // k0 now expired
	c.Put("k1", []Vuln{{ID: "CVE-2"}}) // triggers a purge
	if _, ok := c.Get("k0"); ok {
		t.Fatal("expired entry should have been purged on put")
	}
	if _, ok := c.Get("k1"); !ok {
		t.Fatal("fresh entry should be present")
	}
}

func TestCacheTTLExpiryViaInjectedNow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewCache(time.Hour, 8, func() time.Time { return now })
	c.Put("k", []Vuln{{ID: "CVE-1"}})
	if _, ok := c.Get("k"); !ok {
		t.Fatal("fresh entry should be retrievable")
	}
	now = now.Add(59 * time.Minute)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry just inside the TTL should still be retrievable")
	}
	now = now.Add(2 * time.Minute) // 61m total — past the 1h TTL
	if _, ok := c.Get("k"); ok {
		t.Fatal("entry past the TTL should be expired")
	}
}

func TestBuildDenyMessageAndVulnIDs(t *testing.T) {
	vulns := []Vuln{{ID: "CVE-2021-1234", Summary: "test summary"}, {ID: "GHSA-abc"}}
	if got := BuildDenyMessage("lodash", "4.17.20", vulns); got != "lodash@4.17.20 has known vulnerabilities: CVE-2021-1234,GHSA-abc (test summary)" {
		t.Fatalf("deny message = %q", got)
	}
	if got := BuildDenyMessage("lodash", "4.17.20", nil); got != "lodash@4.17.20 has known vulnerabilities: " {
		t.Fatalf("deny message (empty) = %q", got)
	}
	ids := VulnIDs(vulns)
	if len(ids) != 2 || ids[0] != "CVE-2021-1234" || ids[1] != "GHSA-abc" {
		t.Fatalf("vuln ids = %v", ids)
	}
}
