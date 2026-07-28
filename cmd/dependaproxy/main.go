// Package main is the DependaProxy entrypoint: load config, open storage, build
// the npm registry client and server, and serve.
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
	"github.com/psenna/dependaproxy/internal/registry/npm"
	"github.com/psenna/dependaproxy/internal/server"
	"github.com/psenna/dependaproxy/internal/storage"
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

	st, err := storage.OpenPostgres(ctx, cfg.Storage.DSN)
	if err != nil {
		logger.Error("open storage", "err", err)
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	regClient, err := npm.New(cfg.Upstream, nil)
	if err != nil {
		logger.Error("registry client", "err", err)
		os.Exit(1)
	}

	srv, err := server.New(ctx, cfg, st, regClient)
	if err != nil {
		logger.Error("build server", "err", err)
		os.Exit(1)
	}
	defer func() { _ = srv.Close() }()

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

	logger.Info("dependaproxy starting", "addr", cfg.Server.Addr, "upstream", cfg.Upstream)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}
