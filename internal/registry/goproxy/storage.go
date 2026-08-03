package goproxy

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/storage/db"
)

//go:embed schema.sql
var schemaSQL string

// Record is a validated Go module entry: (module_path, version) key + sha256
// trust anchor + timestamp + JSON metadata.
type Record struct {
	ModulePath     string
	Version        string
	ValidationHash string
	ValidatedAt    time.Time
	Metadata       []byte
}

// Store persists validated goproxy module records. *Storage implements it;
// tests may use an in-memory implementation.
type Store interface {
	Get(ctx context.Context, modulePath, version string) (Record, error)
	Put(ctx context.Context, r Record) error
}

// Storage persists validated module records in the shared Postgres pool.
type Storage struct {
	db *sql.DB
}

// OpenStorage applies the goproxy schema to the shared pool and returns a
// Storage.
func OpenStorage(ctx context.Context, d *sql.DB) (*Storage, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &Storage{db: d}, nil
}

// Get returns the record for (module_path, version), or ErrNotFound.
func (s *Storage) Get(ctx context.Context, modulePath, version string) (Record, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT validation_hash, validated_at, metadata
		FROM goproxy_validated_modules
		WHERE module_path = $1 AND version = $2`, modulePath, version)
	var r Record
	var meta []byte
	err := row.Scan(&r.ValidationHash, &r.ValidatedAt, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("goproxy storage get: %w", err)
	}
	r.ModulePath, r.Version, r.Metadata = modulePath, version, meta
	return r, nil
}

// Put upserts the record on (module_path, version).
func (s *Storage) Put(ctx context.Context, r Record) error {
	var meta any
	if r.Metadata != nil {
		meta = string(r.Metadata)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO goproxy_validated_modules (module_path, version, validation_hash, validated_at, metadata)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (module_path, version) DO UPDATE
		SET validation_hash = EXCLUDED.validation_hash,
		    validated_at    = EXCLUDED.validated_at,
		    metadata        = EXCLUDED.metadata`,
		r.ModulePath, r.Version, r.ValidationHash, r.ValidatedAt, meta)
	if err != nil {
		return fmt.Errorf("goproxy storage put: %w", err)
	}
	return nil
}
