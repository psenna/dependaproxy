# internal/webui

This package embeds the DependaProxy web dashboard into the Go binary via
`//go:embed` (issue #152).

## How the embed works

- The embed source lives in `internal/webui/dist`. `//go:embed` cannot
  reference paths outside the package directory, so the built UI is copied
  here rather than embedded from `web/dist` directly.
- A minimal placeholder `internal/webui/dist/index.html` is committed so the
  build compiles on a fresh checkout (before the web UI has been built).
- `make web-sync` copies `web/dist` into `internal/webui/dist`, overwriting
  the placeholder with the real Vite build. It is a no-op when `web/dist` is
  absent.
- The Dockerfile's `web-build` stage builds the UI and the `build` stage
  overlays the result into `/src/internal/webui/dist` before `go build`, so
  container images always embed the real dashboard.
- To restore the committed placeholder (e.g. after a local `make web-sync`):
  `git checkout internal/webui/dist/index.html`.

## Handler behavior

`webui.Handler()` serves static files from the embedded dist (hashed assets
under `assets/` get `Cache-Control: public, max-age=31536000, immutable`) and
falls back to `index.html` for any other path, so client-side routes work on
refresh (SPA fallback).
