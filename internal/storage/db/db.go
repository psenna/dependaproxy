// Package db provides a shared PostgreSQL connection pool used by every
// registry adapter's storage. The pgx driver is registered here, once, for the
// whole binary; adapters call ApplySchema with their own embedded schema.
package db

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// OpenPostgres opens a pooled connection to the database at dsn and pings it.
func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	d, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := d.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return d, nil
}

// ApplySchema executes a schema (CREATE TABLE IF NOT EXISTS ...) on the pool.
func ApplySchema(ctx context.Context, d *sql.DB, schema string) error {
	_, err := d.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}
