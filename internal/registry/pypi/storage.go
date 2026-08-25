package pypi

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

// Record is a validated PyPI file: (project_key, name, version, filename) key
// + parsed compatibility tags + sha256 trust anchor + JSON metadata.
// ProjectKey is "" for the projectless (default) scope, matching the
// convention used by the deny list (internal/denylist) and project dependency
// tracker (internal/project).
type Record struct {
	ProjectKey     string
	Name           string
	Version        string
	Filename       string
	FileType       string // "wheel" | "sdist"
	PythonTag      string
	AbiTag         string
	PlatformTag    string
	Sha256         string
	RequiresPython string
	Yanked         bool
	ValidatedAt    time.Time
	Metadata       []byte
}

// Store persists validated PyPI files, scoped per project (H2): a record
// validated under one project's pipeline is never served to a different
// project's requests. *Storage implements it; tests may use an in-memory
// implementation.
type Store interface {
	Get(ctx context.Context, projectKey, name, version, filename string) (Record, error)
	Put(ctx context.Context, r Record) error
}

// Storage persists validated PyPI files in the shared Postgres pool.
type Storage struct {
	db *sql.DB
}

// OpenStorage applies the pypi schema to the shared pool and returns a Storage.
func OpenStorage(ctx context.Context, d *sql.DB) (*Storage, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &Storage{db: d}, nil
}

// Get returns the record for (projectKey, name, version, filename), or
// ErrNotFound.
func (s *Storage) Get(ctx context.Context, projectKey, name, version, filename string) (Record, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT filetype, python_tag, abi_tag, platform_tag, sha256, requires_python, yanked, validated_at, metadata
		FROM pypi_validated_files
		WHERE project_key = $1 AND name = $2 AND version = $3 AND filename = $4`, projectKey, name, version, filename)
	var r Record
	var meta []byte
	err := row.Scan(&r.FileType, &r.PythonTag, &r.AbiTag, &r.PlatformTag, &r.Sha256, &r.RequiresPython, &r.Yanked, &r.ValidatedAt, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("pypi storage get: %w", err)
	}
	r.ProjectKey, r.Name, r.Version, r.Filename, r.Metadata = projectKey, name, version, filename, meta
	return r, nil
}

// Put upserts the record on (project_key, name, version, filename).
func (s *Storage) Put(ctx context.Context, r Record) error {
	var meta any
	if r.Metadata != nil {
		meta = string(r.Metadata)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pypi_validated_files (project_key, name, version, filename, filetype, python_tag, abi_tag, platform_tag, sha256, requires_python, yanked, validated_at, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (project_key, name, version, filename) DO UPDATE
		SET filetype=EXCLUDED.filetype, python_tag=EXCLUDED.python_tag, abi_tag=EXCLUDED.abi_tag,
		    platform_tag=EXCLUDED.platform_tag, sha256=EXCLUDED.sha256, requires_python=EXCLUDED.requires_python,
		    yanked=EXCLUDED.yanked, validated_at=EXCLUDED.validated_at, metadata=EXCLUDED.metadata`,
		r.ProjectKey, r.Name, r.Version, r.Filename, r.FileType, r.PythonTag, r.AbiTag, r.PlatformTag, r.Sha256, r.RequiresPython, r.Yanked, r.ValidatedAt, meta)
	if err != nil {
		return fmt.Errorf("pypi storage put: %w", err)
	}
	return nil
}
