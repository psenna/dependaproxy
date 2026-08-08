// Package denylist persists a Postgres-backed deny list of packages that
// failed validation. Each entry records the package name, version, artifact
// sha256, project key, the validation failure reason, the denying middleware,
// and when the pipeline ran. Matching is strict per scope: a denial recorded
// under a project blocks only that project, and a projectless denial
// (project_key = ”) blocks only projectless requests.
package denylist

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

// Denial records a package that failed validation, keyed by
// (registry, name, version, sha256, project_key).
type Denial struct {
	Registry   string // 'npm' | 'pypi' | 'goproxy'
	Name       string // package name / module path
	Version    string
	ArtifactID string // pypi filename; '' for npm/goproxy
	Sha256     string // lowercase hex sha256 of the tarball
	ProjectKey string // '' = projectless (default) scope
	Reason     string // stored validation failure reason
	Middleware string // middleware that denied
	DeniedAt   time.Time
}

// Store persists denials. *PostgresStore implements it; tests may use an
// in-memory implementation.
type Store interface {
	Lookup(ctx context.Context, registry, name, version, sha256, projectKey string) (reason string, ok bool, err error)
	Record(ctx context.Context, d Denial) error
}

// PostgresStore persists denials in the shared Postgres pool.
type PostgresStore struct {
	db *sql.DB
}

// OpenStore applies the deny-list schema (idempotent) to the shared pool and
// returns a PostgresStore. The pool is shared: no new connection is created.
func OpenStore(ctx context.Context, d *sql.DB) (*PostgresStore, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &PostgresStore{db: d}, nil
}

// Lookup returns the denial reason for an exact (registry, name, version,
// sha256, project_key) match. Matching is strict per scope: a projectless row
// (project_key = ”) never matches a project-scoped lookup, and vice versa.
func (s *PostgresStore) Lookup(ctx context.Context, registry, name, version, sha256, projectKey string) (string, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT reason
		FROM denied_packages
		WHERE registry = $1 AND name = $2 AND version = $3 AND sha256 = $4 AND project_key = $5`,
		registry, name, version, sha256, projectKey)
	var reason string
	err := row.Scan(&reason)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("deny-list lookup: %w", err)
	}
	return reason, true, nil
}

// Record upserts a denial on the primary key, refreshing reason, middleware,
// project_key and denied_at.
func (s *PostgresStore) Record(ctx context.Context, d Denial) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO denied_packages (registry, name, version, artifact_id, sha256, project_key, reason, middleware, denied_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (registry, name, version, sha256, project_key) DO UPDATE
		SET reason      = EXCLUDED.reason,
		    middleware  = EXCLUDED.middleware,
		    project_key = EXCLUDED.project_key,
		    denied_at   = EXCLUDED.denied_at`,
		d.Registry, d.Name, d.Version, d.ArtifactID, d.Sha256, d.ProjectKey, d.Reason, d.Middleware, d.DeniedAt)
	if err != nil {
		return fmt.Errorf("deny-list record: %w", err)
	}
	return nil
}
