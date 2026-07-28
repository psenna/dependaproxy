package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed schema.sql
var schemaSQL string

// Postgres is a Storage backend backed by PostgreSQL via database/sql + the
// pure-Go pgx driver.
type Postgres struct {
	db *sql.DB
}

// OpenPostgres opens the database at dsn, pings it, and applies the schema.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Postgres{db: db}, nil
}

// Get returns the record for the composite key, or ErrNotFound.
func (p *Postgres) Get(ctx context.Context, name, version, registry string) (PackageRecord, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT validation_hash, validated_at, metadata
		FROM validated_packages
		WHERE name = $1 AND version = $2 AND registry = $3`,
		name, version, registry)
	var r PackageRecord
	var meta []byte
	err := row.Scan(&r.ValidationHash, &r.ValidatedAt, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageRecord{}, ErrNotFound
	}
	if err != nil {
		return PackageRecord{}, fmt.Errorf("get: %w", err)
	}
	r.Name, r.Version, r.Registry = name, version, registry
	r.Metadata = meta
	return r, nil
}

// Put upserts the record on the composite key.
func (p *Postgres) Put(ctx context.Context, r PackageRecord) error {
	// metadata is JSON; pass as a string (or NULL) so Postgres accepts it as JSONB.
	var meta any
	if r.Metadata != nil {
		meta = string(r.Metadata)
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO validated_packages (name, version, registry, validation_hash, validated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (name, version, registry) DO UPDATE
		SET validation_hash = EXCLUDED.validation_hash,
		    validated_at    = EXCLUDED.validated_at,
		    metadata        = EXCLUDED.metadata`,
		r.Name, r.Version, r.Registry, r.ValidationHash, r.ValidatedAt, meta)
	if err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

// Close releases the database. Idempotent.
func (p *Postgres) Close() error {
	if p == nil || p.db == nil {
		return nil
	}
	db := p.db
	p.db = nil
	return db.Close()
}
