package cvecheckcache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"github.com/psenna/dependaproxy/internal/storage/db"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping cve-check cache postgres test")
	}
	return dsn
}

func openTestStore(t *testing.T) *PostgresStore {
	t.Helper()
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	st, err := OpenStore(ctx, d)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM middleware_retrieval_cvecheck_cache`); err != nil {
		t.Fatalf("clean cache: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st
}

// TestCountBySeverity is a unit test of the shared cveosv.CountBySeverity
// helper the store persists: vulns tally into bands, with empty/unrecognized
// severities counting as unknown.
func TestCountBySeverity(t *testing.T) {
	vulns := []cveosv.Vuln{
		{ID: "CVE-1", Severity: cveosv.SeverityCritical},
		{ID: "CVE-2", Severity: cveosv.SeverityCritical},
		{ID: "CVE-3", Severity: cveosv.SeverityHigh},
		{ID: "CVE-4", Severity: cveosv.SeverityMedium},
		{ID: "CVE-5", Severity: cveosv.SeverityLow},
		{ID: "CVE-6", Severity: cveosv.SeverityUnknown},
		{ID: "CVE-7"}, // empty severity → unknown
	}
	c := cveosv.CountBySeverity(vulns)
	if c.Critical != 2 || c.High != 1 || c.Medium != 1 || c.Low != 1 || c.Unknown != 2 {
		t.Fatalf("counts = %+v", c)
	}
	if c.Total() != 7 {
		t.Fatalf("total = %d want 7", c.Total())
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	counts := Counts{Critical: 2, High: 1, Unknown: 3}
	if err := st.Put(ctx, "npm", "lodash", "4.17.20", counts, now); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("get returned nil entry")
	}
	if got.Ecosystem != "npm" || got.Name != "lodash" || got.Version != "4.17.20" {
		t.Fatalf("entry key = %+v", got)
	}
	if got.Counts != counts {
		t.Fatalf("counts = %+v want %+v", got.Counts, counts)
	}
	if !got.RetrievedAt.Equal(now) {
		t.Fatalf("retrieved_at = %v want %v", got.RetrievedAt, now)
	}
}

func TestStoreGetMissingReturnsNil(t *testing.T) {
	st := openTestStore(t)
	got, err := st.Get(context.Background(), "npm", "nope", "1.0.0")
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if got != nil {
		t.Fatalf("get missing should return (nil, nil), got %+v", got)
	}
}

func TestStoreUpsertOnConflict(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := st.Put(ctx, "npm", "lodash", "4.17.20", Counts{Critical: 1}, now); err != nil {
		t.Fatalf("put 1: %v", err)
	}
	later := now.Add(time.Hour)
	if err := st.Put(ctx, "npm", "lodash", "4.17.20", Counts{High: 5}, later); err != nil {
		t.Fatalf("put 2: %v", err)
	}
	got, err := st.Get(ctx, "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Counts.Critical != 0 || got.Counts.High != 5 {
		t.Fatalf("upsert should replace counts, got %+v", got.Counts)
	}
	if !got.RetrievedAt.Equal(later) {
		t.Fatalf("upsert should refresh retrieved_at, got %v want %v", got.RetrievedAt, later)
	}
}
