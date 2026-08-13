// Package webui embeds the built DependaProxy web dashboard into the Go binary
// via //go:embed. The embed source is internal/webui/dist (//go:embed cannot
// reference paths outside the package directory). A minimal placeholder
// index.html is committed there so the build compiles on a fresh checkout;
// `make web-build && make web-sync` replaces it with the real Vite build, and
// the Dockerfile overlays the web-build stage's output into the same directory.
// The handler serves static assets with long-lived cache headers and falls back
// to index.html for client-side routes (SPA).
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// FS returns the embedded dist directory as an fs.FS rooted at the build
// output (index.html, assets/, ...).
func FS() fs.FS {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

// Handler returns an http.Handler that serves the embedded web UI: static
// files as-is (hashed assets with immutable cache headers) and any other path
// with index.html so client-side routes work on refresh (SPA fallback).
func Handler() http.Handler { return handler(FS()) }

func handler(root fs.FS) http.Handler {
	fileServer := http.FileServerFS(root)
	indexBytes, err := fs.ReadFile(root, "index.html")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean("/" + r.URL.Path)
		rel := strings.TrimPrefix(clean, "/")
		if rel == "" {
			w.Header().Set("Cache-Control", "no-cache")
			fileServer.ServeHTTP(w, r)
			return
		}
		// http.FileServer redirects /index.html to ./ (301); serve the bytes
		// directly so the canonical document URL returns 200.
		if clean == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(indexBytes)
			return
		}
		if stat, err := fs.Stat(root, rel); err == nil && !stat.IsDir() {
			setCacheHeaders(w, clean)
			fileServer.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexBytes)
	})
}

func setCacheHeaders(w http.ResponseWriter, clean string) {
	switch {
	case clean == "/index.html":
		w.Header().Set("Cache-Control", "no-cache")
	case strings.HasPrefix(clean, "/assets/"):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "no-cache")
	}
}
