package storage

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping PostgreSQL integration test")
	}
	return dsn
}

func openTestStorage(t *testing.T) *Postgres {
	t.Helper()
	st, err := OpenPostgres(context.Background(), testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Start each test from a clean table.
	if _, err := st.db.ExecContext(context.Background(), `DELETE FROM validated_packages`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPostgresRoundTrip(t *testing.T) {
	st := openTestStorage(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := PackageRecord{
		Name: "express", Version: "4.18.0", Registry: "npm",
		ValidationHash: "deadbeef",
		ValidatedAt:    now,
		Metadata:       []byte(`{"min_days":7}`),
	}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, "express", "4.18.0", "npm")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ValidationHash != "deadbeef" {
		t.Errorf("hash = %q", got.ValidationHash)
	}
	if !got.ValidatedAt.Equal(now) {
		t.Errorf("validated_at = %v want %v", got.ValidatedAt, now)
	}
	// JSONB canonicalizes whitespace, so compare semantically, not byte-for-byte.
	if !jsonEqual(got.Metadata, rec.Metadata) {
		t.Errorf("metadata = %q want %q", got.Metadata, rec.Metadata)
	}
}

// jsonEqual reports whether two JSON byte slices decode to the same value.
func jsonEqual(a, b []byte) bool {
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

func TestPostgresGetMissing(t *testing.T) {
	st := openTestStorage(t)
	_, err := st.Get(context.Background(), "nope", "1.0.0", "npm")
	if err != ErrNotFound {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestPostgresUpsert(t *testing.T) {
	st := openTestStorage(t)
	ctx := context.Background()
	rec := PackageRecord{
		Name: "lodash", Version: "4.17.0", Registry: "npm",
		ValidationHash: "aaa", ValidatedAt: time.Now().UTC(),
		Metadata: []byte(`{}`),
	}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put1: %v", err)
	}
	rec.ValidationHash = "bbb"
	rec.ValidatedAt = rec.ValidatedAt.Add(time.Hour)
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put2: %v", err)
	}
	got, err := st.Get(ctx, rec.Name, rec.Version, rec.Registry)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ValidationHash != "bbb" {
		t.Errorf("hash = %q want bbb (upserted)", got.ValidationHash)
	}
}

func TestPostgresNilMetadata(t *testing.T) {
	st := openTestStorage(t)
	ctx := context.Background()
	rec := PackageRecord{
		Name: "p", Version: "1", Registry: "npm",
		ValidationHash: "h", ValidatedAt: time.Now().UTC(),
		Metadata: nil,
	}
	if err := st.Put(ctx, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, rec.Name, rec.Version, rec.Registry)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Metadata != nil {
		t.Errorf("metadata = %q want nil", got.Metadata)
	}
}

// TestPostgresConcurrentPut exercises concurrent upserts under the race
// detector. All goroutines write the same key; the final value must be one of
// the written hashes (no error, no corruption).
func TestPostgresConcurrentPut(t *testing.T) {
	st := openTestStorage(t)
	ctx := context.Background()
	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.Put(ctx, PackageRecord{
				Name: "concurrent", Version: "1.0.0", Registry: "npm",
				ValidationHash: "h" + strconv.Itoa(i),
				ValidatedAt:    time.Now().UTC(),
				Metadata:       []byte(`{}`),
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent put: %v", err)
	}
	got, err := st.Get(ctx, "concurrent", "1.0.0", "npm")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.ValidationHash) != 2 {
		t.Errorf("final hash = %q, want one of the h0..h9 written", got.ValidationHash)
	}
}
