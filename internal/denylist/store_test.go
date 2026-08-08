package denylist

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/storage/db"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping denylist postgres test")
	}
	return dsn
}

// openTestStore opens a fresh pool and Store, cleaning the denied_packages
// table so tests are independent.
func openTestStore(t *testing.T) (*PostgresStore, *sql.DB) {
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
	if _, err := d.ExecContext(ctx, `DELETE FROM denied_packages`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st, d
}

func TestStoreRecordAndLookupRoundTrip(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	d := Denial{
		Registry:   "npm",
		Name:       "express",
		Version:    "4.18.0",
		ArtifactID: "",
		Sha256:     "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8091",
		ProjectKey: "proj-1",
		Reason:     "blocked by policy",
		Middleware: "guarddog-scan",
		DeniedAt:   time.Now().UTC(),
	}
	if err := st.Record(ctx, d); err != nil {
		t.Fatalf("record: %v", err)
	}
	reason, ok, err := st.Lookup(ctx, d.Registry, d.Name, d.Version, d.Sha256, d.ProjectKey)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !ok || reason != d.Reason {
		t.Errorf("lookup = (%q, %v) want (%q, true)", reason, ok, d.Reason)
	}
}

func TestLookupMissingRow(t *testing.T) {
	st, _ := openTestStore(t)
	reason, ok, err := st.Lookup(context.Background(), "npm", "no-such-pkg", "9.9.9", "f0f0f0", "proj-x")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if ok || reason != "" {
		t.Errorf("lookup = (%q, %v) want (\"\", false)", reason, ok)
	}
}

func TestLookupStrictProjectScoping(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	base := Denial{
		Registry:   "pypi",
		Name:       "foo",
		Version:    "1.0",
		ArtifactID: "foo-1.0.tar.gz",
		Sha256:     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		ProjectKey: "", // projectless (default) scope
		Reason:     "projectless denial",
		Middleware: "cve-check",
		DeniedAt:   now,
	}
	if err := st.Record(ctx, base); err != nil {
		t.Fatalf("record projectless: %v", err)
	}
	scoped := base
	scoped.ProjectKey = "proj-a"
	scoped.Reason = "project-scoped denial"
	if err := st.Record(ctx, scoped); err != nil {
		t.Fatalf("record project-scoped: %v", err)
	}

	// A projectless row must not match a project-scoped lookup.
	if reason, ok, err := st.Lookup(ctx, scoped.Registry, scoped.Name, scoped.Version, scoped.Sha256, "proj-a"); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if !ok || reason != scoped.Reason {
		t.Errorf("scoped match = (%q, %v) want (%q, true)", reason, ok, scoped.Reason)
	}

	// A project-scoped row must not match a projectless lookup.
	if _, ok, err := st.Lookup(ctx, base.Registry, base.Name, base.Version, base.Sha256, "proj-b"); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if ok {
		t.Error("projectless denial matched a project-scoped lookup")
	}

	// The projectless lookup matches only the projectless row.
	if reason, ok, err := st.Lookup(ctx, base.Registry, base.Name, base.Version, base.Sha256, ""); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if !ok || reason != base.Reason {
		t.Errorf("projectless match = (%q, %v) want (%q, true)", reason, ok, base.Reason)
	}
}

func TestLookupDifferentSha256(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	d := Denial{
		Registry:   "npm",
		Name:       "lodash",
		Version:    "4.17.0",
		Sha256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ProjectKey: "",
		Reason:     "blocked",
		DeniedAt:   time.Now().UTC(),
	}
	if err := st.Record(ctx, d); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, ok, err := st.Lookup(ctx, d.Registry, d.Name, d.Version, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", d.ProjectKey); err != nil {
		t.Fatalf("lookup: %v", err)
	} else if ok {
		t.Error("lookup matched a different sha256")
	}
}

func TestRecordUpsertSamePrimaryKey(t *testing.T) {
	st, d := openTestStore(t)
	ctx := context.Background()

	rec := Denial{
		Registry:   "goproxy",
		Name:       "example.com/foo",
		Version:    "v1.0.0",
		Sha256:     "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		ProjectKey: "",
		Reason:     "first reason",
		Middleware: "mw-1",
		DeniedAt:   time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
	}
	if err := st.Record(ctx, rec); err != nil {
		t.Fatalf("record: %v", err)
	}

	rec.Reason = "second reason"
	rec.Middleware = "mw-2"
	rec.DeniedAt = time.Now().UTC().Truncate(time.Microsecond)
	if err := st.Record(ctx, rec); err != nil {
		t.Fatalf("re-record: %v", err)
	}

	// Exactly one row for the primary key, with refreshed reason/middleware/denied_at.
	var n int
	if err := d.QueryRowContext(ctx, `
		SELECT count(*) FROM denied_packages
		WHERE registry = $1 AND name = $2 AND version = $3 AND sha256 = $4 AND project_key = $5`,
		rec.Registry, rec.Name, rec.Version, rec.Sha256, rec.ProjectKey).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("row count = %d want 1", n)
	}

	reason, ok, err := st.Lookup(ctx, rec.Registry, rec.Name, rec.Version, rec.Sha256, rec.ProjectKey)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !ok || reason != "second reason" {
		t.Errorf("lookup = (%q, %v) want (%q, true)", reason, ok, "second reason")
	}

	var deniedAt time.Time
	if err := d.QueryRowContext(ctx, `
		SELECT denied_at FROM denied_packages
		WHERE registry = $1 AND name = $2 AND version = $3 AND sha256 = $4 AND project_key = $5`,
		rec.Registry, rec.Name, rec.Version, rec.Sha256, rec.ProjectKey).Scan(&deniedAt); err != nil {
		t.Fatalf("denied_at: %v", err)
	}
	if !deniedAt.Equal(rec.DeniedAt) {
		t.Errorf("denied_at = %v want %v", deniedAt, rec.DeniedAt)
	}
}
