# DependaProxy

DependaProxy is a secure dependency proxy that mitigates software supply-chain
attacks. Instead of letting builds download packages directly from public
registries, it validates each package through a configurable middleware
pipeline, stores a strong cryptographic hash of the validated artifact, and
later serves packages only if the served bytes match the stored hash.

**v2 is multi-registry:** one instance serves several registries at the same
time, segregated by URL path prefix (`/npm/…`, `/pypi/…`, `/maven/…`), via a
shared core + per-registry **adapter** plugins. Clients point their package
manager at the proxy with no client-side changes beyond the registry/index URL.

## Architecture

```
                  ┌───────────────────────────┐
   client ──────▶│  server (prefix-dispatch) │  /healthz (open) + shared bearer auth
                  │  /<prefix>/… → adapter   │
                  └──────────┬────────────────┘
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
     npm adapter        pypi adapter     maven adapter
     /npm/…             /pypi/…          /maven/… (skeleton)
     └─────────────── shared core ───────────────┘
        pipeline engine (generic ctx), localcache, mutation,
        hash, log, config, auth, postgres pool, adapter registry
```

Adding a registry = one package under `internal/registry/<x>` + one
`adapter.Register` call; the shared core never changes.

**Trust flow (per adapter, same shape):** `mutation.PreFetch → storage.Get →
` trusted (retrieval cache→upstream + constant-time sha256 verify; mismatch →
evict + refetch + reverify, persistent mismatch → 502 never serve) **or**
untrusted (retrieval + validation → sha256 → store) `→ mutation.PostFetch →
serve`. Validation rejection → 403; upstream 404 → 404; upstream error → 502.

## Adapters

- **npm** (`/npm/`): packument route (rewrites `dist.tarball` to the proxy) +
  tarball route. Store keyed on `(name, version)`. Min-publication-age reads the
  npm `time` map.
- **pypi** (`/pypi/`): PEP 691 JSON index route (`/pypi/simple/{name}/`, file
  urls rewritten to `/pypi/files/{name}/{version}/{filename}`) + file route.
  **Per-file store** keyed on `(name, version, filename)` with parsed
  `filetype`/`python_tag`/`abi_tag`/`platform_tag` (the architecture) + sha256 —
  PyPI has multiple files per version (wheels per platform + sdist), so the
  trust anchor is per-file. Min-publication-age reads per-file `upload-time`.
- **maven** (`/maven/`): skeleton (maven-metadata model + 501 placeholder);
  full routing/storage is a future issue.

## Configuration

See `config.example.yaml`:

| Field | Description |
|---|---|
| `server.addr` | HTTP listen address (default `:8080`). |
| `auth.token` | Static bearer token shared across all registries. Empty disables. |
| `storage.type` / `storage.dsn` | Shared PostgreSQL (one pool; each adapter owns its table). |
| `log.level` / `log.format` | `debug\|info\|warn\|error` and `json\|text`. |
| `registries[]` | `{type, prefix, upstream, validation[], retrieval[], mutation[]}` per registry. |

```yaml
registries:
  - type: npm
    prefix: /npm
    upstream: https://registry.npmjs.org
    validation: [{type: min-publication-age, params: {min_days: 7}}]
    retrieval: [{type: local-disk-cache, params: {path: /cache/npm}}, {type: upstream-registry}]
  - type: pypi
    prefix: /pypi
    upstream: https://pypi.org/simple
    validation: [{type: min-publication-age, params: {min_days: 7}}]
    retrieval: [{type: local-disk-cache, params: {path: /cache/pypi}}, {type: upstream-registry}]
```

## Quickstart

```sh
make db      # postgres:18 container (db=dependaproxy, pw=secret)
make run     # go run ./cmd/dependaproxy   (uses config.yaml; see config.example.yaml)
```

Point your package managers at the proxy:

```sh
npm install --registry http://localhost:8080/npm <pkg>            # npm
pip download --index-url http://localhost:8080/pypi/simple <pkg>  # pip
```

With `auth.token` set, configure the credential too (`npm config set
//localhost:8080/:_authToken <token>`, `pip config set global.index-url
http://user:token@localhost:8080/pypi/simple`).

## Development & testing

```sh
make test      # go test -race -p 1 -coverprofile=cover.out ./...  (DinD golang:1.25)
make vet       # go vet ./...
make fmt-check # fail on gofmt drift
make lint      # golangci-lint
make vuln      # govulncheck
```

Integration tests that need PostgreSQL read `DP_TEST_PG_DSN` (skipped when unset;
CI sets it against a `postgres:18` service). `-p 1` serializes the shared-DB
integration tests. The build is CGo-free except the race detector.

## Security model

- **Trust only validated artifacts**: per-artifact sha256 computed on validation
  and re-verified in constant time on every retrieval; mismatch is never served.
- **Fail closed**: min-publication-age rejects when publication time is
  unavailable; upstream sha256 mismatches are rejected (defense-in-depth).
- **Tamper-resistant cache**: corrupted/tampered local cache files are caught at
  hash-verify, evicted, refetched, and re-verified.
- **Shared static bearer token**, compared in constant time, never logged.
- **Minimal dependencies**: `gopkg.in/yaml.v3` + `github.com/jackc/pgx/v5` only.

## Feature roadmap

### Implemented
- ☑ Multi-registry platform (one instance, many registries, path-prefix segregation)
- ☑ Adapter plugin model (new registry = one package + one `adapter.Register`)
- ☑ npm adapter (packument + tarball, `dist.tarball` rewrite, `(name,version)` store)
- ☑ pypi adapter (PEP 691 JSON, per-file store with platform/python/abi tags)
- ☑ sha256 trust anchor (per-artifact, constant-time verify, evict+refetch+reverify, 502 on persistent mismatch)
- ☑ Minimum Publication Age (npm `time`; pypi per-file `upload-time`; fail-closed; injectable clock)
- ☑ Local Disk Cache (write-through, generic per-artifact keying, per-key lock)
- ☑ Mutation pipeline PreFetch/PostFetch hooks (NoOp shipped; real mutations via config)
- ☑ Static bearer-token auth (shared across registries, /healthz exempt, constant-time)
- ☑ YAML config (multi-registry: per-registry upstream/middleware; shared storage/auth/log)
- ☑ Middleware plugin architecture (new middleware = one file + one config entry)
- ☑ Maven adapter skeleton (types + factory + registration; routes/storage deferred)
- ☑ TDD: unit + per-adapter + multi-registry e2e + mutation contract; CI (vet/gofmt/golangci-lint/govulncheck/race+coverage)

### Planned / future
- ☐ Full Maven adapter (maven-metadata.xml routing, `(groupId,artifactId,version,classifier,type)` store, upstream fetch)
- ☐ Additional registries (Cargo, NuGet, Go modules) via the adapter contract
- ☐ CVE / vulnerability validation middleware
- ☐ Malware / heuristic static-analysis validation middleware
- ☐ AI-assisted validation middleware
- ☐ S3 / object-store cache backend
- ☐ Policy engine (allow/deny lists, license, dependency constraints)
- ☐ Auth / RBAC (token scopes, per-registry/per-package permissions)
- ☐ Metrics & observability (Prometheus, tracing, audit log)
- ☐ Package provenance verification (npm sigstore, PEP 740, Maven PGP)
- ☐ Yanked-file filtering middleware
- ☐ Mutations: strip install scripts / files from wheels, sdists, jars
- ☐ Rate limiting & quota
- ☐ Web UI / admin dashboard
- ☐ Multi-algorithm trust anchor (sha256 + blake2b/sha512)