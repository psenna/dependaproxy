package npm

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

// Record is a validated npm package entry: (project_key, name, version) key +
// sha256 trust anchor + timestamp + JSON metadata. ProjectKey is "" for the
// projectless (default) scope, matching the convention used by the deny list
// (internal/denylist) and project dependency tracker (internal/project).
type Record struct {
	ProjectKey     string
	Name           string
	Version        string
	ValidationHash string
	ValidatedAt    time.Time
	Metadata       []byte
}

// Store persists validated npm records, scoped per project (H2): a record
// validated under one project's pipeline is never served to a different
// project's requests. *Storage implements it; tests may use an in-memory
// implementation.
type Store interface {
	Get(ctx context.Context, projectKey, name, version string) (Record, error)
	Put(ctx context.Context, r Record) error
}

// Storage persists validated npm package records in the shared Postgres pool.
type Storage struct {
	db *sql.DB
}

// OpenStorage applies the npm schema to the shared pool and returns a Storage.
func OpenStorage(ctx context.Context, d *sql.DB) (*Storage, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &Storage{db: d}, nil
}

// Get returns the record for (projectKey, name, version), or ErrNotFound.
func (s *Storage) Get(ctx context.Context, projectKey, name, version string) (Record, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT validation_hash, validated_at, metadata
		FROM npm_validated_packages
		WHERE project_key = $1 AND name = $2 AND version = $3`, projectKey, name, version)
	var r Record
	var meta []byte
	err := row.Scan(&r.ValidationHash, &r.ValidatedAt, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("npm storage get: %w", err)
	}
	r.ProjectKey, r.Name, r.Version, r.Metadata = projectKey, name, version, meta
	return r, nil
}

// Put upserts the record on (project_key, name, version).
func (s *Storage) Put(ctx context.Context, r Record) error {
	var meta any
	if r.Metadata != nil {
		meta = string(r.Metadata)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO npm_validated_packages (project_key, name, version, validation_hash, validated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (project_key, name, version) DO UPDATE
		SET validation_hash = EXCLUDED.validation_hash,
		    validated_at    = EXCLUDED.validated_at,
		    metadata        = EXCLUDED.metadata`,
		r.ProjectKey, r.Name, r.Version, r.ValidationHash, r.ValidatedAt, meta)
	if err != nil {
		return fmt.Errorf("npm storage put: %w", err)
	}
	return nil
}
