// Package main is the DependaProxy entrypoint: load config, open the shared
// postgres pool, build the multi-registry server (npm/pypi/maven/... adapters),
// and serve. Registry adapters register themselves via init() side effects.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	_ "github.com/psenna/dependaproxy/internal/registry/maven" // register the maven adapter (skeleton)
	_ "github.com/psenna/dependaproxy/internal/registry/npm"   // register the npm adapter
	_ "github.com/psenna/dependaproxy/internal/registry/pypi"  // register the pypi adapter
	"github.com/psenna/dependaproxy/internal/server"
	"github.com/psenna/dependaproxy/internal/storage/db"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	d, err := db.OpenPostgres(ctx, cfg.Storage.DSN)
	if err != nil {
		logger.Error("open storage", "err", err)
		os.Exit(1)
	}

	srv, err := server.New(ctx, cfg, d)
	if err != nil {
		logger.Error("build server", "err", err)
		os.Exit(1)
	}
	// Shutdown drains the dependency tracker and closes the DB on every exit path
	// (the explicit drain below handles the normal/error serve return; this covers
	// early returns between here and the listener).
	defer func() { _ = srv.Shutdown(context.Background()) }()

	httpSrv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sCancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logger.Info("dependaproxy starting", "addr", cfg.Server.Addr, "registries", len(cfg.Registries))
	serveErr := httpSrv.ListenAndServe()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		logger.Error("serve", "err", serveErr)
	}
	// The http server has returned (graceful shutdown on ctx.Done, or an error),
	// so no new requests can enqueue; drain buffered dependency records (bounded
	// by a 10s context) before the DB closes.
	drainCtx, dCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := srv.Shutdown(drainCtx); err != nil {
		logger.Warn("drain dependency tracker", "err", err)
	}
	dCancel()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		os.Exit(1)
	}
}
