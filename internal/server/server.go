// Package server is the multi-registry HTTP front door. It builds the
// configured registry adapters, mounts each at its URL path prefix, and wraps
// everything in the shared token auth (with /healthz open).
package server

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/admin"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/log"
	"github.com/psenna/dependaproxy/internal/project"
)

// Server is the aggregate HTTP server for all configured registries.
type Server struct {
	cfg          *config.Config
	db           *sql.DB
	adapters     []adapter.Adapter
	projectStore project.Store
	depStore     project.DependencyStore
	tracker      *project.Tracker
	logger       *slog.Logger
}

// New opens no resources itself; it builds the adapters from cfg using the
// shared db pool. The caller owns db (or hands it to Close/Shutdown). When db is
// non-nil it also opens the dependency store and starts the download tracker
// that adapters share.
func New(ctx context.Context, cfg *config.Config, db *sql.DB) (*Server, error) {
	logger := log.New(cfg.Log.Format, cfg.Log.Level)
	deps := adapter.Deps{DB: db, Logger: logger, Now: func() time.Time { return time.Now().UTC() }}
	// The project + dependency stores share the DB pool. nil db is used by
	// dispatch-only tests with fake adapters that never touch storage; the store
	// and tracker stay nil there.
	var projectStore project.Store
	var depStore project.DependencyStore
	var tracker *project.Tracker
	if db != nil {
		ps, err := project.OpenStore(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("open project store: %w", err)
		}
		projectStore = ps
		deps.ProjectStore = ps

		ds, err := project.OpenDependencyStore(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("open dependency store: %w", err)
		}
		depStore = ds
		tracker = project.NewTracker(depStore, project.TrackerConfig{FlushInterval: 5 * time.Second, DropInterval: 5 * time.Second, BatchSize: 100}, logger)
		if err := tracker.Start(ctx); err != nil {
			return nil, fmt.Errorf("start dependency tracker: %w", err)
		}
		deps.DependencyTracker = tracker
	}
	adapters, err := adapter.Build(ctx, cfg.Registries, deps)
	if err != nil {
		if tracker != nil {
			_ = tracker.Shutdown(context.Background())
		}
		return nil, err
	}
	return &Server{cfg: cfg, db: db, adapters: adapters, projectStore: projectStore, depStore: depStore, tracker: tracker, logger: logger}, nil
}

// Handler returns the HTTP handler: /healthz (open) + one mount per adapter at
// its prefix, all wrapped by TokenAuth (shared token, /healthz exempt).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	// The admin API is mounted on the same mux so the shared TokenAuth wrap
	// below gates it. It is only present when a project store exists (db != nil);
	// the dependency store is non-nil exactly then too.
	if s.projectStore != nil {
		ah := admin.New(s.projectStore, s.depStore, adapterInvalidator{s.adapters}, s.logger, knownRegistryTypes(s.cfg))
		mux.Handle("/admin/", http.StripPrefix("/admin", ah.Handler()))
	}
	for _, a := range s.adapters {
		prefix := strings.TrimRight(a.Prefix(), "/")
		mux.Handle(prefix+"/", http.StripPrefix(prefix, a.Handler()))
	}
	exempt := func(p string) bool { return p == "/healthz" }
	return TokenAuth(s.cfg.Auth.Token, exempt, s.logger, mux)
}

// adapterInvalidator fans a project cache invalidation out to every configured
// registry adapter, so each adapter's project.Resolver drops its cached
// pipelines for that key.
type adapterInvalidator struct {
	adapters []adapter.Adapter
}

// Invalidate drops the cached Resolved pipelines for key in every adapter.
func (a adapterInvalidator) Invalidate(key string) {
	for _, ad := range a.adapters {
		ad.InvalidateProjectCache(key)
	}
}

// knownRegistryTypes returns the configured registry adapter types (e.g.
// ["npm", "pypi"]) in config order, for the admin API's registry validation.
func knownRegistryTypes(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	types := make([]string, 0, len(cfg.Registries))
	for _, r := range cfg.Registries {
		types = append(types, r.Type)
	}
	return types
}

// Shutdown drains the dependency tracker (flushing buffered records) and then
// closes the shared database pool. It is idempotent and safe on the db==nil
// dispatch-only path, where no tracker was started.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.tracker != nil {
		_ = s.tracker.Shutdown(ctx)
	}
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Close releases the shared database pool, draining the tracker with a
// background context. Kept for back-compat; prefer Shutdown with a bounded
// context.
func (s *Server) Close() error {
	return s.Shutdown(context.Background())
}
