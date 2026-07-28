// Package main is the DependaProxy entrypoint. v1 scaffold: logs a startup
// line and exits. Subsequent issues wire config, pipelines, storage and the
// HTTP server here.
package main

import (
	"log/slog"
	"os"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("dependaproxy starting")
}
