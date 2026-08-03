// Package project persists and resolves per-project middleware overrides.
// A project config is a key plus per-registry middleware lists (validation /
// retrieval / mutation) that differ from the global defaults; registries absent
// from the map fall back to the global pipelines.
package project

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/storage/db"
	"gopkg.in/yaml.v3"
)

//go:embed schema.sql
var schemaSQL string

// ErrProjectNotFound is returned by Get when no project config exists for a key.
var ErrProjectNotFound = errors.New("project: not found")

// ProjectConfig is the per-project override for a registry: a key plus the
// per-registry middleware lists that differ from the global defaults.
type ProjectConfig struct {
	Key        string
	Registries map[string]config.RegistryMiddlewareConfig
}

// Store persists per-project middleware overrides. *Storage implements it;
// tests may use an in-memory implementation.
type Store interface {
	Get(ctx context.Context, key string) (ProjectConfig, error)
	Put(ctx context.Context, cfg ProjectConfig) error
	List(ctx context.Context) ([]ProjectConfig, error)
	Delete(ctx context.Context, key string) error
}

// Storage persists project configs in the shared Postgres pool.
type Storage struct {
	db *sql.DB
}

// OpenStore applies the projects schema to the shared pool and returns a
// Storage sharing the pool.
func OpenStore(ctx context.Context, d *sql.DB) (*Storage, error) {
	if err := db.ApplySchema(ctx, d, schemaSQL); err != nil {
		return nil, err
	}
	return &Storage{db: d}, nil
}

// Get returns the project config for key, or ErrProjectNotFound.
func (s *Storage) Get(ctx context.Context, key string) (ProjectConfig, error) {
	var configText string
	row := s.db.QueryRowContext(ctx, `SELECT config FROM projects WHERE key=$1`, key)
	err := row.Scan(&configText)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectConfig{}, ErrProjectNotFound
	}
	if err != nil {
		return ProjectConfig{}, fmt.Errorf("project storage get: %w", err)
	}
	registries, err := decodeConfig(configText)
	if err != nil {
		return ProjectConfig{}, err
	}
	return ProjectConfig{Key: key, Registries: registries}, nil
}

// Put upserts the project config on key.
func (s *Storage) Put(ctx context.Context, cfg ProjectConfig) error {
	data, err := yaml.Marshal(cfg.Registries)
	if err != nil {
		return fmt.Errorf("project storage encode config: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO projects (key, config) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE
		SET config = EXCLUDED.config, updated_at = now()`,
		cfg.Key, string(data))
	if err != nil {
		return fmt.Errorf("project storage put: %w", err)
	}
	return nil
}

// List returns all project configs ordered by key.
func (s *Storage) List(ctx context.Context) ([]ProjectConfig, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, config FROM projects ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("project storage list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ProjectConfig
	for rows.Next() {
		var key, configText string
		if err := rows.Scan(&key, &configText); err != nil {
			return nil, fmt.Errorf("project storage list: %w", err)
		}
		registries, err := decodeConfig(configText)
		if err != nil {
			return nil, err
		}
		out = append(out, ProjectConfig{Key: key, Registries: registries})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("project storage list: %w", err)
	}
	return out, nil
}

// Delete removes the project config for key; a missing key is not an error.
func (s *Storage) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE key=$1`, key)
	if err != nil {
		return fmt.Errorf("project storage delete: %w", err)
	}
	return nil
}

// decodeConfig parses a stored YAML document into a per-registry middleware
// map. An empty document decodes to an empty map.
func decodeConfig(configText string) (map[string]config.RegistryMiddlewareConfig, error) {
	registries := map[string]config.RegistryMiddlewareConfig{}
	if strings.TrimSpace(configText) == "" {
		return registries, nil
	}
	if err := yaml.Unmarshal([]byte(configText), &registries); err != nil {
		return nil, fmt.Errorf("project storage decode config: %w", err)
	}
	if registries == nil {
		registries = map[string]config.RegistryMiddlewareConfig{}
	}
	return registries, nil
}
