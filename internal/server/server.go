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
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/log"
	"github.com/psenna/dependaproxy/internal/project"
)

// Server is the aggregate HTTP server for all configured registries.
type Server struct {
	cfg      *config.Config
	db       *sql.DB
	adapters []adapter.Adapter
	logger   *slog.Logger
}

// New opens no resources itself; it builds the adapters from cfg using the
// shared db pool. The caller owns db (or hands it to Close).
func New(ctx context.Context, cfg *config.Config, db *sql.DB) (*Server, error) {
	logger := log.New(cfg.Log.Format, cfg.Log.Level)
	deps := adapter.Deps{DB: db, Logger: logger, Now: func() time.Time { return time.Now().UTC() }}
	// The project store shares the DB pool. nil db is used by dispatch-only tests
	// with fake adapters that never touch storage; ProjectStore stays nil there.
	if db != nil {
		projectStore, err := project.OpenStore(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("open project store: %w", err)
		}
		deps.ProjectStore = projectStore
	}
	adapters, err := adapter.Build(cfg.Registries, deps)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, db: db, adapters: adapters, logger: logger}, nil
}

// Handler returns the HTTP handler: /healthz (open) + one mount per adapter at
// its prefix, all wrapped by TokenAuth (shared token, /healthz exempt).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	for _, a := range s.adapters {
		prefix := strings.TrimRight(a.Prefix(), "/")
		mux.Handle(prefix+"/", http.StripPrefix(prefix, a.Handler()))
	}
	exempt := func(p string) bool { return p == "/healthz" }
	return TokenAuth(s.cfg.Auth.Token, exempt, s.logger, mux)
}

// Close releases the shared database pool.
func (s *Server) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}
