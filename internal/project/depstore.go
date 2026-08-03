package project

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/storage/db"
)

// maxBatchRows caps the number of records per multi-row INSERT statement.
const maxBatchRows = 500

// DependencyRecord is one artifact download attributed to a project. The
// (project_key, registry, pkg, version, artifact_id, sha256) tuple is the
// identity; re-downloads increment download_count instead of inserting a row.
type DependencyRecord struct {
	ProjectKey        string
	Registry          string
	Pkg               string
	Version           string
	ArtifactID        string
	SHA256            string
	FirstDownloadedAt time.Time
	LastDownloadedAt  time.Time
	DownloadCount     int64
}

// DependencyListFilters filters List results; a zero-value field is ignored.
type DependencyListFilters struct {
	Registry string
	Pkg      string
}

// DependencyStore persists per-project artifact download records. *DependencyStorage
// implements it; the tracker depends on this interface so tests can substitute a
// fake.
type DependencyStore interface {
	UpsertBatch(ctx context.Context, recs []DependencyRecord) error
	List(ctx context.Context, projectKey string, f DependencyListFilters) ([]DependencyRecord, error)
}

// DependencyStorage persists dependency download records in the shared Postgres pool.
type DependencyStorage struct {
	db *sql.DB
}

// OpenDependencyStore applies the projects + project_dependencies schema to the
// shared pool and returns a DependencyStorage sharing the pool.
func OpenDependencyStore(ctx context.Context, d *sql.DB) (*DependencyStorage, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &DependencyStorage{db: d}, nil
}

// UpsertBatch inserts or increments dependency download records in one statement,
// chunked to <= maxBatchRows rows per statement. Identical identities within a
// batch are aggregated so a single statement never targets the same row twice.
// Each record's DownloadCount is added to any existing row with the same
// (project_key, registry, pkg, version, artifact_id, sha256) identity;
// first_downloaded_at is preserved on conflict.
func (s *DependencyStorage) UpsertBatch(ctx context.Context, recs []DependencyRecord) error {
	if len(recs) == 0 {
		return nil
	}
	for start := 0; start < len(recs); start += maxBatchRows {
		end := start + maxBatchRows
		if end > len(recs) {
			end = len(recs)
		}
		if err := s.upsertChunk(ctx, recs[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (s *DependencyStorage) upsertChunk(ctx context.Context, recs []DependencyRecord) error {
	// Aggregate duplicate identities within the chunk: two rows with the same
	// (project_key, registry, pkg, version, artifact_id, sha256) in one statement
	// would make ON CONFLICT DO UPDATE target the same row twice, which Postgres
	// rejects ("cannot affect row a second time").
	merged := make([]DependencyRecord, 0, len(recs))
	idx := map[string]int{}
	for _, r := range recs {
		// Each record carries a download count of 1; an unset (<=0) count is
		// normalized so the INSERT never writes 0.
		count := r.DownloadCount
		if count <= 0 {
			count = 1
		}
		key := r.ProjectKey + "\x00" + r.Registry + "\x00" + r.Pkg + "\x00" +
			r.Version + "\x00" + r.ArtifactID + "\x00" + r.SHA256
		if i, ok := idx[key]; ok {
			merged[i].DownloadCount += count
			continue
		}
		r.DownloadCount = count
		idx[key] = len(merged)
		merged = append(merged, r)
	}

	var buf bytes.Buffer
	buf.WriteString(`INSERT INTO project_dependencies (project_key, registry, pkg, version, artifact_id, sha256, download_count) VALUES `)
	args := make([]any, 0, len(merged)*7)
	for i, r := range merged {
		if i > 0 {
			buf.WriteString(", ")
		}
		base := i * 7
		fmt.Fprintf(&buf, "($%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7)
		args = append(args, r.ProjectKey, r.Registry, r.Pkg, r.Version, r.ArtifactID, r.SHA256, r.DownloadCount)
	}
	buf.WriteString(` ON CONFLICT (project_key, registry, pkg, version, artifact_id, sha256) DO UPDATE
SET last_downloaded_at = now(), download_count = project_dependencies.download_count + EXCLUDED.download_count`)
	if _, err := s.db.ExecContext(ctx, buf.String(), args...); err != nil {
		return fmt.Errorf("dependency storage upsert: %w", err)
	}
	return nil
}

// List returns dependency records for a project, optionally filtered by registry
// and package, ordered by registry, pkg, version, artifact_id.
func (s *DependencyStorage) List(ctx context.Context, projectKey string, f DependencyListFilters) ([]DependencyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT project_key, registry, pkg, version, artifact_id, sha256,
		       first_downloaded_at, last_downloaded_at, download_count
		FROM project_dependencies
		WHERE project_key = $1 AND ($2 = '' OR registry = $2) AND ($3 = '' OR pkg = $3)
		ORDER BY registry, pkg, version, artifact_id`, projectKey, f.Registry, f.Pkg)
	if err != nil {
		return nil, fmt.Errorf("dependency storage list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DependencyRecord
	for rows.Next() {
		var r DependencyRecord
		if err := rows.Scan(&r.ProjectKey, &r.Registry, &r.Pkg, &r.Version, &r.ArtifactID, &r.SHA256,
			&r.FirstDownloadedAt, &r.LastDownloadedAt, &r.DownloadCount); err != nil {
			return nil, fmt.Errorf("dependency storage list: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dependency storage list: %w", err)
	}
	return out, nil
}
