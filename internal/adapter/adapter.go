// Package adapter defines the registry-adapter plugin contract. Each registry
// (npm, pypi, maven, ...) is an Adapter built by a Factory from its
// RegistryConfig + shared Deps. The server builds all configured adapters and
// mounts each at its prefix. Adding a registry = one new package under
// internal/registry/<x> + one adapter.Register call; the shared core never
// changes.
package adapter

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/project"
)

// Deps are shared dependencies passed to every adapter factory.
type Deps struct {
	DB           *sql.DB // shared postgres connection pool
	ProjectStore project.Store
	Logger       *slog.Logger
	Now          func() time.Time
}

// Adapter is one registry plugin. It owns its data model, client, routes,
// per-registry middleware, and storage schema.
type Adapter interface {
	// Prefix is the URL path prefix this adapter is mounted at (e.g. "/npm").
	Prefix() string
	// Handler serves this registry's routes. The server strips the prefix
	// before dispatching, so the handler sees paths relative to its prefix.
	Handler() http.Handler
}

// Factory builds an adapter from its RegistryConfig + shared Deps.
type Factory func(cfg config.RegistryConfig, deps Deps) (Adapter, error)

var factories = map[string]Factory{}

// Register registers an adapter factory by registry type. Called from each
// adapter package (via cmd/main import side-effects or explicit init).
func Register(typeName string, f Factory) {
	factories[typeName] = f
}

// Build builds all adapters for the configured registries, rejecting unknown
// types.
func Build(cfgs []config.RegistryConfig, deps Deps) ([]Adapter, error) {
	out := make([]Adapter, 0, len(cfgs))
	for i, rc := range cfgs {
		f, ok := factories[rc.Type]
		if !ok {
			return nil, fmt.Errorf("registries[%d]: unknown registry type %q", i, rc.Type)
		}
		a, err := f(rc, deps)
		if err != nil {
			return nil, fmt.Errorf("registries[%d] %s: %w", i, rc.Type, err)
		}
		out = append(out, a)
	}
	return out, nil
}
