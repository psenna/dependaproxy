# DependaProxy

DependaProxy is a secure dependency proxy that mitigates software supply-chain
attacks. Instead of letting builds download packages directly from public
registries, it validates each package through a configurable middleware
pipeline, stores a strong cryptographic hash of the validated artifact, and
later serves packages only if the served bytes match the stored hash.

It is registry-compatible: clients point their package manager at DependaProxy
instead of the public registry, with no client-side changes.

> **Status:** v1. v1 supports the **npm** registry, one validation middleware
> (Minimum Publication Age), one retrieval middleware (Local Disk Cache),
> YAML configuration, a PostgreSQL-backed record store, static-token auth, and
> an npm-compatible proxy endpoint. The architecture is middleware-based and
> extensible — additional registries, validation, retrieval, and mutation
> middleware slot in via config without redesign.

## v1 scope

- npm registry only (drop-in replacement for the default npm registry).
- Validation middleware: **Minimum Publication Age** — reject packages
  published less than N configurable days ago.
- Retrieval middleware: **Local Disk Cache** — write-through cache of validated
  tarballs to avoid repeated upstream fetches.
- YAML configuration for middleware ordering, parameters, cache location, DB.
- PostgreSQL store of validated package records (name, version, registry,
  validation hash, timestamp).
- Static bearer-token auth on protected routes (`/healthz` exempt).
- npm-compatible proxy endpoint.

## Architecture

DependaProxy is built around three ordered middleware pipelines plus a trust
anchor (the stored sha256 of a validated tarball).

```
                         ┌─────────────────┐
   npm client ─── GET ──▶│  HTTP server     │  routes:
                         │  /healthz (open) │   packument  GET /<pkg>
                         │  /<pkg>          │   tarball    GET /<pkg>/-/<version>
                         │  /<pkg>/-/<ver>  │
                         └────────┬────────┘
                                  │
   Tarball request flow:
                                  │
            mutation.PreFetch (no-op in v1)
                                  │
                       storage.Get(name, version, registry)
                          │                  │
                  found (trusted)      not found (untrusted)
                          │                  │
                  retrieval chain     retrieval chain ──▶ validation chain
                  (cache → upstream)    (cache → upstream)
                          │                  │
                  verify sha256 ==       min-publication-age
                  stored hash ?              │
                          │                  │
                match → serve        compute sha256 ──▶ storage.Put
                mismatch → evict +         │
                refetch + reverify    mutation.PostFetch → serve
                (still bad → 502)
```

**Validation pipeline** — linear chain; the first middleware that rejects
aborts the request (403). v1 ships `min-publication-age`.

**Retrieval pipeline** — decorator chain; the outermost middleware is tried
first (cache), and on a miss it calls the next (upstream), write-through caching
the result. v1 ships `local-disk-cache` → `upstream-registry`.

**Trust anchor** — `sha256(tarball bytes)` stored on validation. Every retrieval
recomputes the hash and compares it in constant time; a mismatch (tampered
cache, corrupted disk, upstream drift) is never served.

The packument route (`GET /<pkg>`) proxies the full upstream packument and
rewrites each version's `dist.tarball` to point at the proxy, so clients fetch
tarballs through the trust flow. All packument fields (dependencies, etc.) are
preserved.

## Configuration

DependaProxy is configuration-driven (YAML). See `config.example.yaml`:

| Field | Description |
|---|---|
| `server.addr` | HTTP listen address (default `:8080`). |
| `auth.token` | Static bearer token for protected routes. Empty disables auth (local dev). |
| `storage.type` / `storage.dsn` | v1: `postgres` + a libpq-style DSN. |
| `registry` | v1: `npm` (default if omitted). |
| `upstream` | Upstream registry URL to fetch/validate against. |
| `log.level` / `log.format` | `debug\|info\|warn\|error` and `json\|text`. |
| `validation` | Ordered validation middleware; each `{type, params}`. |
| `retrieval` | Ordered retrieval middleware (decorator chain). |
| `mutation` | Ordered mutation middleware; empty injects a no-op. |

## Quickstart

The host has no Go toolchain; all Go commands run inside a disposable
`golang:1.25` container via the rootless DinD daemon (see `CLAUDE.md`). `make`
handles the wiring:

```sh
make db      # start a postgres:18 container (db=dependaproxy, pw=secret)
make run     # go run ./cmd/dependaproxy   (uses config.yaml by default)
make test    # go test -race -coverprofile=cover.out ./...
make lint    # golangci-lint run ./...
make vuln    # govulncheck ./...
```

Then point npm at the proxy:

```sh
npm install --registry=http://localhost:8080 <package>
# or persistently:
npm config set registry http://localhost:8080
```

If `auth.token` is set, pass it:

```sh
npm config set //localhost:8080/:_authToken <token>
```

## Development & testing

```sh
make test      # unit + integration tests (race + coverage)
make vet       # go vet
make fmt-check # fail on gofmt drift
make lint      # golangci-lint
make vuln      # govulncheck
```

Integration tests that need PostgreSQL read the DSN from `DP_TEST_PG_DSN`
(skipped when unset); CI sets it against a `postgres:18` service. The build is
CGo-free except the race detector (which links the race runtime via gcc in the
`golang:1.25` image).

## Security model

- **Trust only validated artifacts.** A package is served only after its sha256
  was computed and stored on validation, and every later retrieval re-verifies
  the served bytes against that stored hash in constant time.
- **Fail closed.** Minimum Publication Age rejects when a publication time is
  unavailable (cannot prove age). Integrity mismatch is never served (502).
- **Tamper-resistant cache.** A corrupted/tampered local cache file is detected
  at hash-verify time: the cache entry is evicted, the package is refetched, and
  re-verified; a persistent mismatch is rejected.
- **No upstream token on the proxy.** The proxy fetches from the public upstream
  with its own outbound client; client auth to the proxy is a static bearer
  token. The configured token is compared in constant time and never logged.
- **Minimal dependencies.** Only `gopkg.in/yaml.v3` (config) and
  `github.com/jackc/pgx/v5` (PostgreSQL) are external; everything else is the
  standard library. The build is CGo-free.