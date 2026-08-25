package pypi

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/storage/db"
)

func pTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping pypi postgres test")
	}
	return dsn
}

func openPypiStorage(t *testing.T) *Storage {
	t.Helper()
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, pTestDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	st, err := OpenStorage(ctx, d)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM pypi_validated_files`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st
}

func TestPypiStorageRoundTrip(t *testing.T) {
	st := openPypiStorage(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := Record{
		Name: "numpy", Version: "1.26.0", Filename: "numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl",
		FileType: "wheel", PythonTag: "cp312", AbiTag: "cp312", PlatformTag: "manylinux_2_17_x86_64",
		Sha256: "abc", RequiresPython: ">=3.8", Yanked: false, ValidatedAt: now, Metadata: []byte(`{}`),
	}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, rec.ProjectKey, rec.Name, rec.Version, rec.Filename)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Sha256 != "abc" || got.PythonTag != "cp312" || got.PlatformTag != "manylinux_2_17_x86_64" || got.FileType != "wheel" {
		t.Errorf("got = %+v", got)
	}
	if !got.ValidatedAt.Equal(now) {
		t.Errorf("validated_at = %v want %v", got.ValidatedAt, now)
	}
}

func TestPypiStorageGetMissing(t *testing.T) {
	st := openPypiStorage(t)
	_, err := st.Get(context.Background(), "", "nope", "1.0.0", "f.whl")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestPypiStorageUpsert(t *testing.T) {
	st := openPypiStorage(t)
	ctx := context.Background()
	rec := Record{Name: "p", Version: "1", Filename: "p-1-py3-none-any.whl", FileType: "wheel", Sha256: "aaa", ValidatedAt: time.Now().UTC()}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.Sha256 = "bbb"
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, rec.ProjectKey, rec.Name, rec.Version, rec.Filename)
	if err != nil || got.Sha256 != "bbb" {
		t.Fatalf("upsert: got %+v err %v", got, err)
	}
}

// TestPypiStorageScopedByProject is the regression test for the storage half
// of H2: two different projects' records for the identical (name, version,
// filename) must be independent -- neither Get nor Put may cross project
// scope.
func TestPypiStorageScopedByProject(t *testing.T) {
	st := openPypiStorage(t)
	ctx := context.Background()
	base := Record{Name: "scoped", Version: "1", Filename: "scoped-1-py3-none-any.whl", FileType: "wheel", ValidatedAt: time.Now().UTC()}

	projA := base
	projA.ProjectKey, projA.Sha256 = "proj-a", "sha-a"
	if err := st.Put(ctx, projA); err != nil {
		t.Fatal(err)
	}
	projB := base
	projB.ProjectKey, projB.Sha256 = "proj-b", "sha-b"
	if err := st.Put(ctx, projB); err != nil {
		t.Fatal(err)
	}
	unscoped := base
	unscoped.Sha256 = "sha-unscoped"
	if err := st.Put(ctx, unscoped); err != nil {
		t.Fatal(err)
	}

	gotA, err := st.Get(ctx, "proj-a", base.Name, base.Version, base.Filename)
	if err != nil || gotA.Sha256 != "sha-a" {
		t.Fatalf("proj-a: got %+v err %v", gotA, err)
	}
	gotB, err := st.Get(ctx, "proj-b", base.Name, base.Version, base.Filename)
	if err != nil || gotB.Sha256 != "sha-b" {
		t.Fatalf("proj-b: got %+v err %v", gotB, err)
	}
	gotDefault, err := st.Get(ctx, "", base.Name, base.Version, base.Filename)
	if err != nil || gotDefault.Sha256 != "sha-unscoped" {
		t.Fatalf("default scope: got %+v err %v", gotDefault, err)
	}
	if _, err := st.Get(ctx, "proj-c", base.Name, base.Version, base.Filename); err != ErrNotFound {
		t.Fatalf("proj-c (never written): err = %v want ErrNotFound", err)
	}
}

func TestPypiStorageConcurrentPut(t *testing.T) {
	st := openPypiStorage(t)
	ctx := context.Background()
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.Put(ctx, Record{Name: "c", Version: "1", Filename: "c-1-py3-none-any.whl", FileType: "wheel", Sha256: "h", ValidatedAt: time.Now().UTC()}); err != nil {
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
