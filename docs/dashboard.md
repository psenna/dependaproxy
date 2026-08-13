---
layout: page
title: Dashboard
---

{% include nav.md %}

# Web UI / admin dashboard

DependaProxy ships a small admin dashboard: a React + Vite SPA embedded into the
Go binary via `//go:embed`, so **one process** serves the package registries
(`/npm/…`, `/pypi/…`, `/goproxy/…`), the admin REST API (`/admin/…`), and the
dashboard itself (`/` and `/admin`). No separate frontend server or build step
at deploy time.

## Access (fail-closed)

The dashboard is gated by the **dedicated `auth.admin_token`** — the same token
that guards the admin REST API (privilege separation: the registry `auth.token`
alone cannot open the dashboard). If `auth.admin_token` is blank, the dashboard
is effectively disabled: every API call returns `401` and the login page shows
"Admin token not configured on the server; set `auth.admin_token` in config."

## Login flow

1. An unauthenticated visit to any dashboard route redirects to `/login`.
2. The login form stores the admin token in **`sessionStorage`** (cleared on
   logout / tab close) and sends it as a `Bearer` header on every admin API call.
3. On success the app redirects back to the originally requested route.

## Screens

- **Dashboard** (`/`) — proxy health (`/healthz`) and the project count.
- **Projects** (`/projects`) — the project list with per-project registries,
  plus delete-with-confirmation.
- **New project** (`/projects/new`) — create a project: key + per-registry
  middleware chains (validation / retrieval / mutation).
- **Project detail** (`/projects/{key}`) — the project's config and its **SBOM**
  (dependency records) with client-side registry/package filters.
- **Edit project** (`/projects/{key}/edit`) — upsert the project's config with
  per-chain "override (else inherit global)" toggles.

## Development

```sh
make web-install  # npm ci (node:22-alpine DinD container)
make web-build    # npm ci && npm run build
make web-sync     # copy web/dist -> internal/webui/dist (the //go:embed source)
make web-unit     # vitest unit tests
make web-lint     # eslint + tsc
make web-e2e      # Playwright e2e (chromium, MSW-mocked admin API)
make web-test     # web-lint + web-unit + web-e2e
```

For a hot-reload dev loop run `npm run dev` inside `web/` (Vite dev server;
point it at a real backend with `VITE_API_BASE`).

## Building and embedding

`make web-sync` copies the Vite build output (`web/dist`) into
`internal/webui/dist`, which the Go binary embeds via `//go:embed all:dist`
(`internal/webui`). The Dockerfile's `web-build` stage rebuilds the SPA and
overlays it into the embed directory, so the published image always contains the
real dashboard. A minimal placeholder `index.html` is committed in
`internal/webui/dist` so a fresh checkout compiles before the first `web-build`.

## Limitations

The dashboard exposes **projects CRUD + SBOM viewing** only. Registry-level
configuration (the `registries:` block in `config.example.yaml`), the persistent
deny list, and RBAC are not exposed — those remain file/API concerns.
