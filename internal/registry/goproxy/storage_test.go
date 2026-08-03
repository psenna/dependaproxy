package goproxy

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
		t.Skip("DP_TEST_PG_DSN not set; skipping goproxy postgres test")
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
	if _, err := d.ExecContext(ctx, `DELETE FROM goproxy_validated_modules`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st, d
}

func TestGoproxyStorageRoundTrip(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := Record{ModulePath: "github.com/Azure/azure-sdk-for-go", Version: "v1.0.0", ValidationHash: "abc", ValidatedAt: now, Metadata: []byte(`{"k":"v"}`)}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, "github.com/Azure/azure-sdk-for-go", "v1.0.0")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ValidationHash != "abc" || !got.ValidatedAt.Equal(now) {
		t.Errorf("got = %+v", got)
	}
}

func TestGoproxyStorageGetMissing(t *testing.T) {
	st, _ := openTestStorage(t)
	_, err := st.Get(context.Background(), "example.com/nope", "v1.0.0")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestGoproxyStorageUpsert(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	rec := Record{ModulePath: "github.com/foo/bar", Version: "v1.2.3", ValidationHash: "aaa", ValidatedAt: time.Now().UTC()}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.ValidationHash = "bbb"
	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "github.com/foo/bar", "v1.2.3")
	if err != nil || got.ValidationHash != "bbb" {
		t.Fatalf("upsert: got %+v err %v", got, err)
	}
}

func TestGoproxyStorageConcurrentPut(t *testing.T) {
	st, _ := openTestStorage(t)
	ctx := context.Background()
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := st.Put(ctx, Record{ModulePath: "github.com/c", Version: "v1", ValidationHash: "h", ValidatedAt: time.Now().UTC()}); err != nil {
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
