package npm

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/storage/db"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping npm postgres test")
	}
	return dsn
}

func openTestStorage(t *testing.T) (*Storage, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	st, err := OpenStorage(ctx, d)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM npm_validated_packages`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st, d
}

func TestNpmStorageRoundTrip(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := Record{Name: "express", Version: "4.18.0", ValidationHash: "abc", ValidatedAt: now, Metadata: []byte(`{"k":"v"}`)}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, rec.ProjectKey, "express", "4.18.0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ValidationHash != "abc" || !got.ValidatedAt.Equal(now) {
		t.Errorf("got = %+v", got)
	}
}

func TestNpmStorageGetMissing(t *testing.T) {
	st, _ := openTestStorage(t)
	_, err := st.Get(context.Background(), "", "nope", "1.0.0")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestNpmStorageUpsert(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	rec := Record{Name: "lodash", Version: "4.17.0", ValidationHash: "aaa", ValidatedAt: time.Now().UTC()}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.ValidationHash = "bbb"
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, rec.ProjectKey, "lodash", "4.17.0")
	if err != nil || got.ValidationHash != "bbb" {
		t.Fatalf("upsert: got %+v err %v", got, err)
	}
}

// TestNpmStorageScopedByProject is the regression test for the storage half
// of H2: two different projects' records for the identical (name, version)
// must be independent -- neither Get nor Put may cross project scope.
func TestNpmStorageScopedByProject(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	base := Record{Name: "scoped", Version: "1.0.0", ValidatedAt: time.Now().UTC()}

	projA := base
	projA.ProjectKey, projA.ValidationHash = "proj-a", "hash-a"
	if err := st.Put(ctx, projA); err != nil {
		t.Fatal(err)
	}
	projB := base
	projB.ProjectKey, projB.ValidationHash = "proj-b", "hash-b"
	if err := st.Put(ctx, projB); err != nil {
		t.Fatal(err)
	}
	unscoped := base
	unscoped.ValidationHash = "hash-unscoped"
	if err := st.Put(ctx, unscoped); err != nil {
		t.Fatal(err)
	}

	gotA, err := st.Get(ctx, "proj-a", base.Name, base.Version)
	if err != nil || gotA.ValidationHash != "hash-a" {
		t.Fatalf("proj-a: got %+v err %v", gotA, err)
	}
	gotB, err := st.Get(ctx, "proj-b", base.Name, base.Version)
	if err != nil || gotB.ValidationHash != "hash-b" {
		t.Fatalf("proj-b: got %+v err %v", gotB, err)
	}
	gotDefault, err := st.Get(ctx, "", base.Name, base.Version)
	if err != nil || gotDefault.ValidationHash != "hash-unscoped" {
		t.Fatalf("default scope: got %+v err %v", gotDefault, err)
	}
	if _, err := st.Get(ctx, "proj-c", base.Name, base.Version); err != ErrNotFound {
		t.Fatalf("proj-c (never written): err = %v want ErrNotFound", err)
	}
}

func TestNpmStorageConcurrentPut(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.Put(ctx, Record{Name: "c", Version: "1", ValidationHash: "h", ValidatedAt: time.Now().UTC()}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent: %v", err)
	}
}
