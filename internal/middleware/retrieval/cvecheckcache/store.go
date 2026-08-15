// Package cvecheckcache persists cve-check-retrieval OSV query results as
// severity-band counts in Postgres, so a proxy restart does not re-query OSV
// for every package on the next serve. The table follows the
// middleware_<chain>_<middleware>_<purpose> naming convention: chain=retrieval,
// middleware=cvecheck (the cve-check-retrieval config type with hyphens
// stripped), purpose=cache. Counts are stored AFTER the min_severity filter the
// shared cveosv.Client applies, so a row's counts reflect exactly what the
// middleware would act on at store time; the retrieval middleware re-applies the
// current min_severity threshold on read (FilterByMinSeverity) so a config
// change is honored without a re-query.
package cvecheckcache

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

// Counts is the per-severity-band vuln count for one package version.
type Counts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Total returns the sum of every band.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Unknown
}

// Entry is one cached cve-check-retrieval result.
type Entry struct {
	Ecosystem   string
	Name        string
	Version     string
	Counts      Counts
	RetrievedAt time.Time
}

// Store persists cve-check-retrieval results. *PostgresStore implements it;
// tests may use an in-memory implementation.
type Store interface {
	Get(ctx context.Context, ecosystem, name, version string) (*Entry, error)
	Put(ctx context.Context, ecosystem, name, version string, counts Counts, retrievedAt time.Time) error
}

// PostgresStore persists results in the shared Postgres pool.
type PostgresStore struct {
	db *sql.DB
}

// OpenStore applies the cve-check-retrieval cache schema (idempotent) to the
// shared pool and returns a PostgresStore. The pool is shared: no new
// connection is created.
func OpenStore(ctx context.Context, d *sql.DB) (*PostgresStore, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &PostgresStore{db: d}, nil
}

// Get returns the cached entry for one (ecosystem, name, version), or (nil,
// nil) when no row exists.
func (s *PostgresStore) Get(ctx context.Context, ecosystem, name, version string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT ecosystem, name, version, critical, high, medium, low, unknown, retrieved_at
		FROM middleware_retrieval_cvecheck_cache
		WHERE ecosystem = $1 AND name = $2 AND version = $3`,
		ecosystem, name, version)
	var e Entry
	err := row.Scan(&e.Ecosystem, &e.Name, &e.Version, &e.Counts.Critical, &e.Counts.High, &e.Counts.Medium, &e.Counts.Low, &e.Counts.Unknown, &e.RetrievedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cve-check cache get: %w", err)
	}
	return &e, nil
}

// Put upserts a cached result on the primary key, refreshing the counts and
// retrieved_at.
func (s *PostgresStore) Put(ctx context.Context, ecosystem, name, version string, counts Counts, retrievedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO middleware_retrieval_cvecheck_cache (ecosystem, name, version, critical, high, medium, low, unknown, retrieved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (ecosystem, name, version) DO UPDATE
		SET critical     = EXCLUDED.critical,
		    high         = EXCLUDED.high,
		    medium       = EXCLUDED.medium,
		    low          = EXCLUDED.low,
		    unknown      = EXCLUDED.unknown,
		    retrieved_at = EXCLUDED.retrieved_at`,
		ecosystem, name, version, counts.Critical, counts.High, counts.Medium, counts.Low, counts.Unknown, retrievedAt)
	if err != nil {
		return fmt.Errorf("cve-check cache put: %w", err)
	}
	return nil
}
