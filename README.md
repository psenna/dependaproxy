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
    validation:
      - {type: min-publication-age, params: {min_days: 7}}
      - {type: cve-check, params: {mode: deny}}
      - {type: malware-scan, params: {mode: deny}}
    retrieval:
      - {type: cve-check-retrieval, params: {mode: deny}}  # MUST be first
      - {type: local-disk-cache, params: {path: /cache/npm}}
      - {type: upstream-registry}
  - type: pypi
    prefix: /pypi
    upstream: https://pypi.org/simple
    validation:
      - {type: min-publication-age, params: {min_days: 7}}
      - {type: cve-check, params: {mode: deny}}
      - {type: malware-scan, params: {mode: deny}}
    retrieval:
      - {type: cve-check-retrieval, params: {mode: deny}}  # MUST be first
      - {type: local-disk-cache, params: {path: /cache/pypi}}
      - {type: upstream-registry}
```

### Validation middlewares

- `min-publication-age` — rejects packages published less than `min_days` ago.
- `cve-check` — queries **OSV.dev** (covers npm + PyPI) for known vulnerabilities
  at validation time. Params: `endpoint` (default `https://api.osv.dev`), `mode:
  deny|warn` (default `deny` → 403), `on_error: fail_open|fail_closed` (default
  `fail_open`), `timeout`, `cache_ttl` (in-memory result cache so repeat installs
  don't hammer OSV).
- `malware-scan` — static heuristics on the artifact bytes (already fetched by
  the pipeline when validation runs): npm install scripts (`preinstall` /
  `install` / `postinstall`) + suspicious script contents (curl/wget/base64/
  eval/child_process/external URLs); pypi sdist `setup.py`/`setup.cfg`/`PKG-INFO`
  patterns (exec/eval/base64/os.system/subprocess/socket/curl/wget) and wheels
  with `setup.py` or executable files. Params: `mode: deny|warn` (default `deny`).

> **Validation runs once per artifact.** A package is validated on first fetch
> and stored with its sha256 trust anchor; later retrievals serve the stored
> bytes without re-validating. The `cve-check-retrieval` middleware (below)
> closes the resulting gap: a CVE published *after* first validation is caught
> on the next serve even though the stored artifact is not re-validated.

### Retrieval middlewares

- `cve-check-retrieval` — re-checks **OSV.dev** (npm + PyPI) on **every serve**,
  on both the trusted (storage / cache-hit) and untrusted (fresh fetch) paths.
  It must be **FIRST in the `retrieval:` list** (outermost) so it runs even when
  a downstream cache middleware serves the artifact. Params: `endpoint` (default
  `https://api.osv.dev`), `mode: deny|warn` (default `deny` → 403 via the
  retrieval-rejected error path, with the CVE IDs in the response body),
  `on_error: fail_open|fail_closed` (default `fail_open` — an OSV outage serves;
  `fail_closed` returns a 502, an outage rather than an advisory),
  `timeout`, `cache_ttl` (one OSV call per `cache_ttl` window per
  ecosystem/name/version — a bounded TTL cache shared with the validation
  `cve-check` via the same `internal/middleware/cveosv` client logic).
  When both the validation `cve-check` and `cve-check-retrieval` are configured,
  the first untrusted fetch makes **two** OSV calls (one per middleware — they
  use **separate** caches); subsequent serves make **zero** calls while the TTL
  caches are warm. In v1 the middleware only denies or warns — eviction of the
  stored (already-trusted) record on a new advisory is deferred.

### Cache backends (retrieval)

- `local-disk-cache` — write-through disk cache. Params: `path`.
- `s3-cache` — write-through cache on any S3-compatible object store (AWS S3,
  MinIO, GCS XML API). Params: `endpoint` (host[:port], **no scheme**), `bucket`,
  `region`, `access_key`, `secret_key`, `use_ssl`, `base_path` (optional
  object-key prefix). Exercised by real-MinIO integration tests (see
  Development & testing).
- `upstream-registry` — the terminal fetcher; always last in the chain.

> Both cache backends share one retrieval middleware over a `CacheBackend`
> interface (identical keying/hash-verify/eviction); `local-disk-cache` and
> `s3-cache` differ only in storage.

### Mutation middlewares

- `strip-install-scripts` (npm only) — strips `preinstall`/`install`/`postinstall`
  from `package/package.json` scripts (other scripts preserved), repacks the
  tarball deterministically. Best-effort: a tarball with no package.json or an
  invalid archive is served unchanged.

Mutations are **non-persistent view transforms** re-applied on every serve
(trusted + untrusted): the stored sha256 remains the *upstream* hash; the
mutation rewrites the bytes served to the client **after** verification.
Re-tarring on every serve adds CPU; a follow-up will cache mutated bytes.

Validation (incl. malware-scan) runs on the **original upstream bytes before
PostFetch**; the mutator runs after — detect (malware-scan) and remediate
(strip-install-scripts) are complementary.

## Projects (per-project configuration + SBOM)

DependaProxy applies **one global middleware config per registry** by default. A
*project* is an opt-in, SonarQube-style override: a consuming codebase passes a
**project key** in the URL and gets that project's middleware config (e.g. a
project can run `cve-check` in `warn` while the global default is `deny`), and
DependaProxy records every package@version the project downloads as a
per-project **SBOM**. No project key → today's global default, unchanged.

### Project-scoped routing (`/p/<key>`)

The default registry URL is unchanged (`/npm`, `/pypi`). A project-scoped request
inserts `p/<key>/` right after the registry prefix:

| Default | Project-scoped |
|---|---|
| `/npm/<pkg>` | `/npm/p/<key>/<pkg>` |
| `/npm/<pkg>/-/<version>.tgz` | `/npm/p/<key>/<pkg>/-/<version>.tgz` |
| `/pypi/simple/<pkg>/` | `/pypi/p/<key>/simple/<pkg>/` |
| `/pypi/files/<pkg>/<ver>/<file>` | `/pypi/p/<key>/files/<pkg>/<ver>/<file>` |

Collision safety is built into the parser:

- `/npm/p/-/lodash-1.0.0.tgz` is still the **package `p`** tarball (a key of `-`
  is rejected), so the existing `p` package keeps working.
- Scoped packages start with `@` (`/@scope/pkg`) → never collide with `p/`.
- A valid project key matches `^[a-zA-Z0-9._-]+$` and is not `-`.

**Default path is byte-identical to today**: `ProjectKey == ""` short-circuits
before any allocation — no DB lookup, no dependency tracking, no overhead for
existing clients. The global pipelines are pre-cached at startup, so resolving
the default path is a pure in-memory lookup.

### Per-project pipeline resolution

Each adapter holds a `ProjectResolver` that builds and caches middleware
pipelines per project key (reusing the adapter's middleware factories). On a
project-scoped request it resolves the project's config from the `projects`
table and builds the validation/retrieval/mutation chains; on the default path
(or an **unknown** project key, which falls back to global) it returns the
pre-cached global pipelines. Per-chain fallback: a project config that sets
only `npm.validation` reuses the global retrieval/mutation chains. The resolver
cache is invalidated on every admin PUT/DELETE so the next request re-reads the
store.

### Admin REST API (`/admin`)

Projects are managed at runtime through an authenticated REST API mounted at
`/admin`, gated by the **same shared `auth.token`** as the registries (a
dedicated admin token is a future hardening). Routes:

| Method & path | Purpose |
|---|---|
| `POST /admin/projects` | Create a project (409 if the key exists). |
| `GET /admin/projects` | List projects. |
| `GET /admin/projects/{key}` | Get one project's config (404 if missing). |
| `PUT /admin/projects/{key}` | Upsert — create (201) or replace (200) a project's config. |
| `DELETE /admin/projects/{key}` | Delete a project (404 if missing, 204 if present). |
| `GET /admin/projects/{key}/dependencies` | The project's SBOM, with optional `?registry=&pkg=` server-side filters (404 if no records). |

The request/response bodies are JSON; the per-registry middleware `params` are
accepted as a JSON object and bridged to the YAML `params` the existing factory
decode path consumes. After a `PUT` or `DELETE`, the resolver cache for that key
is dropped across every adapter, so the next `/npm/p/<key>/…` request rebuilds
from the updated config (after `DELETE`, the key falls back to the global
default).

### Dependency tracking (the SBOM)

On each successful serve **with `ProjectKey != ""`**, the npm/pypi handlers
enqueue `{projectKey, registry, pkg, version, artifactID, sha256}` to an
in-process **async/buffered tracker** that batch-flushes to the
`project_dependencies` table every few seconds (or on shutdown drain). Default
downloads (`ProjectKey == ""`) are **not** tracked. Records are durable after a
flush; a crash loses only the in-flight buffer. There is no per-request DB
round-trip on the serve path. `GET /admin/projects/{key}/dependencies` reads the
SBOM (the small async-flush window means a freshly-installed package may take a
few seconds to appear).

> **Validation runs once per artifact — still applies per project config.** A
> package is validated on first fetch and stored with its sha256 trust anchor;
> later retrievals serve the stored bytes without re-validating. So changing a
> project's validation config does **not** re-validate an artifact already
> stored under that name+version — only freshly-fetched packages hit the new
> pipeline. (The admin e2e test uses a distinct package name per step for this
> reason.)

> **Known limitation.** Packument/index URL rewriting does not yet embed
> `/p/<key>/`: a project-scoped packument returns `dist.tarball`/file URLs
> pointing at the **default** path, so an automated install that follows the
> rewritten URL loses the project scope (and is served/tracked under the global
> default). That includes `npm install --registry …/npm/p/<key>`: npm fetches
> the packument project-scoped but then downloads the tarball from the rewritten
> `dist.tarball` URL (default path), so the tarball is served under the global
> config and **not** recorded in the project's SBOM. To exercise the project
> pipeline and record an SBOM entry today, request the project-scoped tarball URL
> directly (e.g. `curl http://…/npm/p/<key>/<pkg>/-/<version>.tgz`); preserving
> the prefix through the rewritten URLs — so a plain `npm install --registry
> …/npm/p/<key>` populates the SBOM end-to-end — is a planned follow-up.

### Getting started with projects

```sh
# 1. Create a project "acme" whose npm cve-check warns (global default is deny):
curl -fsS -X POST http://localhost:8080/admin/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"mode":"warn"}}]}}}'

# 2. Install a package through the project pipeline. Request the project-scoped
#    tarball URL directly so the download is validated under acme's config and
#    recorded in acme's SBOM:
curl -fsS http://localhost:8080/npm/p/acme/<pkg>/-/<version>.tgz \
  -H "Authorization: Bearer $TOKEN" -o <pkg>-<version>.tgz
#    (Setting `npm install --registry http://localhost:8080/npm/p/acme` fetches
#    the packument project-scoped, but until the URL-rewrite follow-up lands npm
#    follows the rewritten dist.tarball URL back to the default path, so the
#    tarball is served/tracked under the global default — see the known
#    limitation above.)

# 3. Read the project's SBOM (may take a few seconds for the async flush):
curl -fsS http://localhost:8080/admin/projects/acme/dependencies \
  -H "Authorization: Bearer $TOKEN"
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
CI sets it against a `postgres:18` service). S3-cache integration tests read
`DP_TEST_MINIO_ENDPOINT` / `DP_TEST_MINIO_ACCESS_KEY` / `DP_TEST_MINIO_SECRET_KEY`
(skipped when unset; CI runs them against a real `minio/minio` service, and
`make minio` starts one locally). `-p 1` serializes the shared-DB integration
tests. The build is CGo-free except the race detector.

## Security model

- **Trust only validated artifacts**: per-artifact sha256 computed on validation
  and re-verified in constant time on every retrieval; mismatch is never served.
- **Fail closed**: min-publication-age rejects when publication time is
  unavailable; upstream sha256 mismatches are rejected (defense-in-depth).
- **Vulnerability + malware gates (optional)**: `cve-check` blocks versions with
  known OSV advisories (fail-open on a source outage unless `on_error:
  fail_closed`); `malware-scan` blocks packages whose contents trip static
  heuristics. Both configurable to `warn` (serve + log + annotate).
- **Tamper-resistant cache**: corrupted/tampered cache entries (disk or S3) are
  caught at hash-verify, evicted, refetched, and re-verified.
- **Shared static bearer token**, compared in constant time, never logged.
- **Minimal dependencies**: `gopkg.in/yaml.v3` + `github.com/jackc/pgx/v5` +
  `github.com/minio/minio-go/v7` (S3 cache backend only).

## Feature roadmap

### Implemented
- ☑ Multi-registry platform (one instance, many registries, path-prefix segregation)
- ☑ Adapter plugin model (new registry = one package + one `adapter.Register`)
- ☑ npm adapter (packument + tarball, `dist.tarball` rewrite, `(name,version)` store)
- ☑ pypi adapter (PEP 691 JSON, per-file store with platform/python/abi tags)
- ☑ sha256 trust anchor (per-artifact, constant-time verify, evict+refetch+reverify, 502 on persistent mismatch)
- ☑ Minimum Publication Age (npm `time`; pypi per-file `upload-time`; fail-closed; injectable clock)
- ☑ CVE / vulnerability validation (OSV.dev, npm + PyPI; deny/warn; fail-open/closed on source error)
- ☑ CVE retrieval re-check (`cve-check-retrieval`: OSV re-checked on every serve, trusted + untrusted incl. cache hits, deny/warn, fail-open/closed on source error, bounded TTL cache shared with validation cve-check via `cveosv`) — mitigates the "CVE published after first validation" gap
- ☑ Malware / heuristic static-analysis validation (npm install scripts + suspicious script contents; pypi setup.py/PKG-INFO patterns + wheel exec files; deny/warn)
- ☑ Pluggable cache backend (CacheBackend interface: disk + S3/MinIO write-through with real-MinIO integration tests)
- ☑ Local Disk Cache (write-through, generic per-artifact keying, per-key lock)
- ☑ Mutation pipeline PreFetch/PostFetch hooks (NoOp shipped; strip-install-scripts for npm shipped)
- ☑ Static bearer-token auth (shared across registries, /healthz exempt, constant-time)
- ☑ YAML config (multi-registry: per-registry upstream/middleware; shared storage/auth/log)
- ☑ Middleware plugin architecture (new middleware = one file + one config entry)
- ☑ Maven adapter skeleton (types + factory + registration; routes/storage deferred)
- ☑ Projects: per-project configuration (`/p/<key>` routing, `PipelineContext.ProjectKey`, default-path backward compat)
- ☑ Projects: project config store (postgres `projects` table) + `ProjectResolver` (cached, per-chain fallback to global, invalidated on admin write)
- ☑ Projects: async/buffered dependency tracking + emit on serve (per-project SBOM; zero overhead on the default path)
- ☑ Projects: admin REST API (`/admin/projects` CRUD + cache invalidation; shared `auth.token`)
- ☑ Projects: SBOM query API (`GET /admin/projects/{key}/dependencies` with server-side filters)
- ☑ TDD: unit + per-adapter + multi-registry e2e + mutation contract; CI (vet/gofmt/golangci-lint/govulncheck/race+coverage)

### Planned / future
- ☐ Full Maven adapter (maven-metadata.xml routing, `(groupId,artifactId,version,classifier,type)` store, upstream fetch)
- ☐ Additional registries (Cargo, NuGet, Go modules) via the adapter contract
- ☐ AI-assisted validation middleware
- ☐ Policy engine (allow/deny lists, license, dependency constraints)
- ☐ Auth / RBAC (token scopes, per-registry/per-package permissions)
- ☐ Metrics & observability (Prometheus, tracing, audit log)
- ☐ Package provenance verification (npm sigstore, PEP 740, Maven PGP)
- ☐ Yanked-file filtering middleware
- ☐ Mutations: strip files from pypi wheels/sdists + jars (npm install-scripts shipped); cache mutated bytes (keyed by upstream sha256 + mutator version)
- ☐ Rate limiting & quota
- ☐ Web UI / admin dashboard
- ☐ Multi-algorithm trust anchor (sha256 + blake2b/sha512)