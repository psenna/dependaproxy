package project_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/storage/db"
)

// openTestDependencyStore opens the shared pool, applies the schema via
// OpenDependencyStore, and wipes the dependency table for an isolated run.
func openTestDependencyStore(t *testing.T) (*project.DependencyStorage, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	st, err := project.OpenDependencyStore(ctx, d)
	if err != nil {
		t.Fatalf("open dependency store: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM project_dependencies`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st, d
}

func sampleDependency(sha string) project.DependencyRecord {
	return project.DependencyRecord{
		ProjectKey: "acme",
		Registry:   "npm",
		Pkg:        "testpkg",
		Version:    "1.0.0",
		ArtifactID: "",
		SHA256:     sha,
	}
}

func TestDependencyStoreInsertList(t *testing.T) {
	st, _ := openTestDependencyStore(t)
	ctx := context.Background()
	rec := sampleDependency("abc123")
	if err := st.UpsertBatch(ctx, []project.DependencyRecord{rec}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := st.List(ctx, "acme", project.DependencyListFilters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	r := got[0]
	if r.ProjectKey != "acme" || r.Registry != "npm" || r.Pkg != "testpkg" ||
		r.Version != "1.0.0" || r.ArtifactID != "" || r.SHA256 != "abc123" {
		t.Errorf("record = %+v", r)
	}
	if r.DownloadCount != 1 {
		t.Errorf("download_count = %d, want 1", r.DownloadCount)
	}
	if r.FirstDownloadedAt.IsZero() || r.LastDownloadedAt.IsZero() {
		t.Errorf("timestamps not populated: %+v", r)
	}
}

func TestDependencyStoreDedupIncrements(t *testing.T) {
	st, _ := openTestDependencyStore(t)
	ctx := context.Background()
	rec := sampleDependency("dup")
	// Same identity twice, including within one batch (exercises the intra-batch
	// aggregation that keeps ON CONFLICT from targeting a row twice).
	if err := st.UpsertBatch(ctx, []project.DependencyRecord{rec, rec}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := st.List(ctx, "acme", project.DependencyListFilters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (dedup)", len(got))
	}
	if got[0].DownloadCount != 2 {
		t.Errorf("download_count = %d, want 2", got[0].DownloadCount)
	}
	if got[0].LastDownloadedAt.Before(got[0].FirstDownloadedAt) {
		t.Errorf("last < first: first=%v last=%v", got[0].FirstDownloadedAt, got[0].LastDownloadedAt)
	}
}

func TestDependencyStoreDifferentShaDistinct(t *testing.T) {
	st, _ := openTestDependencyStore(t)
	ctx := context.Background()
	if err := st.UpsertBatch(ctx, []project.DependencyRecord{
		sampleDependency("sha1"),
		sampleDependency("sha2"),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := st.List(ctx, "acme", project.DependencyListFilters{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (different sha256 = distinct rows)", len(got))
	}
}

func TestDependencyStoreListFilters(t *testing.T) {
	st, _ := openTestDependencyStore(t)
	ctx := context.Background()
	recs := []project.DependencyRecord{
		{ProjectKey: "acme", Registry: "npm", Pkg: "left-pad", Version: "1.0.0", SHA256: "a"},
		{ProjectKey: "acme", Registry: "npm", Pkg: "express", Version: "4.0.0", SHA256: "b"},
		{ProjectKey: "acme", Registry: "pypi", Pkg: "requests", Version: "2.0.0", ArtifactID: "requests-2.0.0-py3-none-any.whl", SHA256: "c"},
	}
	if err := st.UpsertBatch(ctx, recs); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	byRegistry, err := st.List(ctx, "acme", project.DependencyListFilters{Registry: "npm"})
	if err != nil {
		t.Fatalf("list registry: %v", err)
	}
	if len(byRegistry) != 2 {
		t.Fatalf("registry filter len = %d, want 2", len(byRegistry))
	}
	for _, r := range byRegistry {
		if r.Registry != "npm" {
			t.Errorf("registry filter returned %q", r.Registry)
		}
	}

	byPkg, err := st.List(ctx, "acme", project.DependencyListFilters{Pkg: "express"})
	if err != nil {
		t.Fatalf("list pkg: %v", err)
	}
	if len(byPkg) != 1 || byPkg[0].Pkg != "express" {
		t.Errorf("pkg filter = %+v, want 1 express row", byPkg)
	}

	byBoth, err := st.List(ctx, "acme", project.DependencyListFilters{Registry: "npm", Pkg: "left-pad"})
	if err != nil {
		t.Fatalf("list both: %v", err)
	}
	if len(byBoth) != 1 || byBoth[0].Pkg != "left-pad" {
		t.Errorf("both filter = %+v, want 1 left-pad row", byBoth)
	}

	// A different project key returns nothing.
	other, err := st.List(ctx, "other", project.DependencyListFilters{})
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("other project len = %d, want 0", len(other))
	}
}
