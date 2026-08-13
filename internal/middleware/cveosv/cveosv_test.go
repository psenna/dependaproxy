package cveosv

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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

// osvServerRaw spins up a fake OSV endpoint returning the given raw vuln maps
// (so tests can exercise severity/database_specific fields the typed Vuln
// struct does not serialize) for any query, and counts how many times it is
// hit.
func osvServerRaw(t *testing.T, raws []map[string]any) (*httptest.Server, *atomic.Int64) {
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
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": raws})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestDefaultedHelpers(t *testing.T) {
	if got := DefaultedEndpoint(""); got != DefaultEndpoint {
		t.Errorf("DefaultedEndpoint(\"\") = %q, want %q", got, DefaultEndpoint)
	}
	if got := DefaultedEndpoint("http://example.com"); got != "http://example.com" {
		t.Errorf("DefaultedEndpoint(non-empty) = %q, want passthrough", got)
	}
	if got := DefaultedMode(""); got != DefaultMode {
		t.Errorf("DefaultedMode(\"\") = %q, want %q", got, DefaultMode)
	}
	if got := DefaultedMode("warn"); got != "warn" {
		t.Errorf("DefaultedMode(non-empty) = %q, want passthrough", got)
	}
	if got := DefaultedOnError(""); got != DefaultOnError {
		t.Errorf("DefaultedOnError(\"\") = %q, want %q", got, DefaultOnError)
	}
	if got := DefaultedOnError("fail_closed"); got != "fail_closed" {
		t.Errorf("DefaultedOnError(non-empty) = %q, want passthrough", got)
	}
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
	if c.MinSeverity() != "" {
		t.Fatalf("min_severity should default to empty, got %q", c.MinSeverity())
	}
}

func TestDefaultedMinSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"high", SeverityHigh},
		{" HIGH ", SeverityHigh},
		{"Critical", SeverityCritical},
		{"medium", SeverityMedium},
		{"low", SeverityLow},
		{"none", ""},
		{"bogus", ""},
	}
	for _, tc := range cases {
		if got := DefaultedMinSeverity(tc.in); got != tc.want {
			t.Errorf("DefaultedMinSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseCVSSBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		ok     bool
	}{
		{"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},                                    // v3.1
		{"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, true},                                    // v3.1
		{"AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0, true},                                    // v3.1 scope-changed
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/BS:9.5", 9.5, true}, // v4 with BS
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.8, true},        // v4 without BS
		{"garbage", 0, false},
		{"AV:N/AC:L", 0, false}, // missing required metrics
	}
	for _, tc := range cases {
		got, ok := parseCVSSBaseScore(tc.vector)
		if ok != tc.ok {
			t.Errorf("parseCVSSBaseScore(%q) ok = %v, want %v", tc.vector, ok, tc.ok)
			continue
		}
		if ok && math.Abs(got-tc.want) > 0.001 {
			t.Errorf("parseCVSSBaseScore(%q) = %v, want %v", tc.vector, got, tc.want)
		}
	}
}

func TestBandFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		{0.1, SeverityLow},
		{0, SeverityLow},
	}
	for _, tc := range cases {
		if got := bandFromScore(tc.score); got != tc.want {
			t.Errorf("bandFromScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestComputeSeverity(t *testing.T) {
	// CVSS score wins over database_specific.severity.
	raw := osvRawVuln{
		ID:       "CVE-1",
		Severity: []osvSeverity{{Type: "CVSS_V3", Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		DatabaseSpecific: struct {
			Severity string `json:"severity"`
		}{Severity: "HIGH"},
	}
	if got := computeSeverity(raw); got != SeverityCritical {
		t.Errorf("computeSeverity with CVSS 9.8 + db HIGH = %q, want critical", got)
	}

	// database_specific.severity fallback (MODERATE → medium).
	raw = osvRawVuln{ID: "CVE-2", DatabaseSpecific: struct {
		Severity string `json:"severity"`
	}{Severity: "MODERATE"}}
	if got := computeSeverity(raw); got != SeverityMedium {
		t.Errorf("computeSeverity with db MODERATE = %q, want medium", got)
	}

	// No severity info → unknown.
	if got := computeSeverity(osvRawVuln{ID: "CVE-3"}); got != SeverityUnknown {
		t.Errorf("computeSeverity with no info = %q, want unknown", got)
	}

	// Highest CVSS score wins.
	raw = osvRawVuln{
		ID: "CVE-4",
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},                             // 5.3
			{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, // 9.8
		},
	}
	if got := computeSeverity(raw); got != SeverityCritical {
		t.Errorf("computeSeverity highest-wins = %q, want critical", got)
	}
}

func TestFilterBySeverity(t *testing.T) {
	vulns := []Vuln{
		{ID: "CVE-1", Severity: SeverityCritical},
		{ID: "CVE-2", Severity: SeverityLow},
		{ID: "CVE-3", Severity: SeverityHigh},
		{ID: "CVE-4", Severity: SeverityUnknown},
	}
	// Mixed: threshold high keeps critical + high.
	got := filterBySeverity(vulns, SeverityHigh)
	if len(got) != 2 || got[0].ID != "CVE-1" || got[1].ID != "CVE-3" {
		t.Fatalf("filterBySeverity(high) = %+v, want CVE-1,CVE-3", got)
	}
	// Unset threshold keeps everything.
	if got := filterBySeverity(vulns, ""); len(got) != 4 {
		t.Fatalf("filterBySeverity(\"\") = %d vulns, want 4", len(got))
	}
	// "none" normalizes to unset → keeps everything.
	if got := filterBySeverity(vulns, SeverityNone); len(got) != 4 {
		t.Fatalf("filterBySeverity(none) = %d vulns, want 4", len(got))
	}
	// Empty input stays empty.
	if got := filterBySeverity(nil, SeverityHigh); len(got) != 0 {
		t.Fatalf("filterBySeverity(nil) = %+v, want empty", got)
	}
}

func TestQueryFiltersByMinSeverity(t *testing.T) {
	srv, hits := osvServerRaw(t, []map[string]any{
		{"id": "CVE-LOW", "database_specific": map[string]any{"severity": "LOW"}},
		{"id": "CVE-HIGH", "database_specific": map[string]any{"severity": "HIGH"}},
		{"id": "CVE-CRIT", "severity": []map[string]any{{"type": "CVSS_V3", "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
	})
	c := NewClient(Params{Endpoint: srv.URL, MinSeverity: SeverityHigh}, nil, func() time.Time { return time.Now().UTC() })
	vulns, err := c.Query(context.Background(), "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns at/above high, got %+v", vulns)
	}
	for _, v := range vulns {
		if v.ID == "CVE-LOW" {
			t.Fatalf("low-severity vuln should be filtered out, got %+v", vulns)
		}
	}
	// The filtered result is cached: a second query must not hit OSV.
	if _, err := c.Query(context.Background(), "npm", "lodash", "4.17.20"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("filtered result should be cached: expected 1 OSV hit, got %d", hits.Load())
	}
}

func TestQueryUnsetThresholdKeepsAll(t *testing.T) {
	srv, _ := osvServerRaw(t, []map[string]any{
		{"id": "CVE-LOW", "database_specific": map[string]any{"severity": "LOW"}},
		{"id": "CVE-HIGH", "database_specific": map[string]any{"severity": "HIGH"}},
	})
	c := NewClient(Params{Endpoint: srv.URL}, nil, func() time.Time { return time.Now().UTC() })
	vulns, err := c.Query(context.Background(), "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("unset threshold should keep all vulns, got %+v", vulns)
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
	if got := BuildDenyMessage("lodash", "4.17.20", vulns, ""); got != "lodash@4.17.20 has known vulnerabilities: CVE-2021-1234,GHSA-abc (test summary)" {
		t.Fatalf("deny message = %q", got)
	}
	if got := BuildDenyMessage("lodash", "4.17.20", nil, ""); got != "lodash@4.17.20 has known vulnerabilities: " {
		t.Fatalf("deny message (empty) = %q", got)
	}
	ids := VulnIDs(vulns)
	if len(ids) != 2 || ids[0] != "CVE-2021-1234" || ids[1] != "GHSA-abc" {
		t.Fatalf("vuln ids = %v", ids)
	}
}

func TestBuildDenyMessageWithSeverity(t *testing.T) {
	vulns := []Vuln{
		{ID: "CVE-2021-1234", Summary: "test summary", Severity: SeverityCritical},
		{ID: "GHSA-abc", Severity: SeverityUnknown},
		{ID: "CVE-2022-5678", Severity: SeverityMedium},
	}
	// With a threshold active, bands are rendered.
	if got := BuildDenyMessage("lodash", "4.17.20", vulns, "high"); got != "lodash@4.17.20 has known vulnerabilities: CVE-2021-1234[critical],GHSA-abc,CVE-2022-5678[medium] (test summary)" {
		t.Fatalf("deny message = %q", got)
	}
	// With no threshold (unset), bare IDs are rendered byte-for-byte identical to
	// the pre-min_severity behavior, even when Severity is populated.
	if got := BuildDenyMessage("lodash", "4.17.20", vulns, ""); got != "lodash@4.17.20 has known vulnerabilities: CVE-2021-1234,GHSA-abc,CVE-2022-5678 (test summary)" {
		t.Fatalf("unset threshold should render bare IDs, got %q", got)
	}
	ids := VulnIDsWithSeverity(vulns)
	if len(ids) != 3 || ids[0] != "CVE-2021-1234[critical]" || ids[1] != "GHSA-abc" || ids[2] != "CVE-2022-5678[medium]" {
		t.Fatalf("vuln ids with severity = %v", ids)
	}
}
