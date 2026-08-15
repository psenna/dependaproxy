---
layout: page
title: Middleware DB tables
---

{% include nav.md %}

# Middleware DB tables

Middleware that persists state to the shared PostgreSQL pool names its table
`middleware_<chain>_<middleware>_<purpose>`:

- `chain` — the pipeline stage the middleware runs in: `retrieval`,
  `validation`, or `mutation`.
- `middleware` — the middleware's config `type:` string with hyphens stripped
  (e.g. `cve-check-retrieval` → `cvecheck`).
- `purpose` — the table's role in the middleware (e.g. `cache`).

| Table | Middleware | Purpose |
| --- | --- | --- |
| `middleware_retrieval_cvecheck_cache` | `cve-check-retrieval` | persistent OSV result cache (severity-band counts) |

Two tables predate the convention and are **not** renamed:

- `denied_packages` — the deny-list store (`denylist` package).
- `project_dependencies` — the per-project dependency/SBOM store (`project`
  package).

## Schema-apply pattern

Each middleware package that owns a table embeds its `schema.sql` with
`//go:embed` and applies it at adapter startup via `db.ApplySchema` (idempotent
`CREATE TABLE IF NOT EXISTS`), so a fresh database is migrated on first boot and
an existing one is left untouched. See
`internal/middleware/retrieval/cvecheckcache` for the pattern.
