package db

import (
	"context"
	"os"
	"testing"
	"time"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping postgres test")
	}
	return dsn
}

func TestOpenAndApplySchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = d.Close() }()
	if err := ApplySchema(ctx, d, `CREATE TABLE IF NOT EXISTS db_smoke (id integer NOT NULL);
		DROP TABLE db_smoke;`); err != nil {
		t.Fatalf("apply: %v", err)
	}
}
