---
layout: page
title: Configuration
---

{% include nav.md %}

# Configuration

DependaProxy is configured with a single YAML file — `config.yaml` at the repo
root when running from source, or mounted at `/config.yaml` when running the
Docker image. Copy [`config.example.yaml`](https://raw.githubusercontent.com/psenna/dependaproxy/main/config.example.yaml)
to get started; the full file is linked at the bottom.

## Top-level fields

| Field | Description |
|---|---|
| `server.addr` | HTTP listen address (default `:8080`). |
| `auth.token` | Static bearer token shared across all registries. Empty disables auth (local dev only). |
| `auth.admin_token` | Dedicated token for the admin API at `/admin` (project config mutations + dependency records). Required when storage is configured; must differ from `auth.token` (privilege separation). Admin mutations are logged at info. |
| `storage.type` / `storage.dsn` | Shared PostgreSQL (one pool; each adapter owns its table). |
| `log.level` / `log.format` | `debug\|info\|warn\|error` and `json\|text`. |
| `registries[]` | One entry per registry: `{type, prefix, upstream, validation[], retrieval[], mutation[]}`. |

## Registries

| Registry | Type | Prefix | Upstream |
|---|---|---|---|
| npm | `npm` | `/npm` | `https://registry.npmjs.org` |
| pypi | `pypi` | `/pypi` | `https://pypi.org/simple` |
| maven (skeleton) | `maven` | `/maven` | `https://repo1.maven.org/maven2` |

### Upstream host allowlist (SSRF hardening)

The npm and pypi upstream clients only fetch from an allowlist of hosts: the
base `upstream` host, plus any hosts listed under `allowed_upstream_hosts`.
Every upstream-advertised URL (npm `dist.tarball` / `dist.attestations.url`,
PyPI file URLs) is validated against this allowlist before the request is made
and again on every redirect hop, so a compromised upstream cannot redirect the
proxy to internal targets (cloud metadata `169.254.169.254`, internal
services). Hostnames are compared case-insensitively on hostname only (any port
is allowed); hostnames that resolve to loopback/private/link-local addresses
are rejected, and DNS failures fail closed.

The **pypi** adapter always includes `files.pythonhosted.org` (PyPI file URLs
live on that host, not `pypi.org`); the **npm** adapter ships no extra default.
Operators of private mirrors add their CDN hosts here:

```yaml
registries:
  - type: npm
    prefix: /npm
    upstream: https://registry.npmjs.org
    allowed_upstream_hosts:
      - cdn.example.com
```

### pypi upstream alias route (`upstream_alias`)

The **pypi** adapter optionally serves a path-mirroring alias:

```
GET /pypi/upstream/{host}/{path...}
```

as an alias for `/pypi/files/{name}/{version}/{filename}`, so a canonical
`uv.lock` / `pdm.lock` (absolute `files.pythonhosted.org` URLs) can be pointed at
the proxy with one reversible substitution. Defaults to `true`; set
`upstream_alias: false` to serve `/simple` + `/files` only.

`{host}` is checked against the **same** `allowed_upstream_hosts` allowlist as
plain membership (no DNS, no private-IP resolution — that check is for outbound
fetches). `{path...}` is routing decoration and is never fetched: the bytes are
resolved through the same trust flow, from the same PEP 691 index lookup, as
`/pypi/files/`, so the route can only name a `(name, version, filename)` triple
that `/pypi/files/` can already name. The route lives outside the simple-API
namespace and is never advertised — PEP 503/691 index output is untouched.

See [Examples #5](examples#5-lockfile-portability-install-a-canonical-uvlock-through-the-proxy).

A registry's middleware lists configure its validation, retrieval, and mutation
pipelines:

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

## Middleware types by stage

**Validation** (runs on first fetch, before the sha256 trust anchor is stored):

- `deny-list-check` — consults the persistent deny list of previously-denied
  (package, version, sha256, project) entries at the start of validation; denies
  fast with the stored reason (403) without re-running the expensive scanners.
  Auto-prepended FIRST for every request scope (projectless and project
  overrides). Strict per-project scoping. Removal via a future admin dashboard.
- `min-publication-age` — rejects packages published less than `min_days` ago
  (npm `time`; pypi per-file `upload-time`; fail-closed).
- `cve-check` — queries **OSV.dev** for known vulnerabilities. Params:
  `endpoint` (default `https://api.osv.dev`), `mode: deny|warn` (default `deny` →
  403), `on_error: fail_open|fail_closed` (default `fail_open`), `timeout`,
  `cache_ttl` (in-memory result cache).
- `malware-scan` — static heuristics on the artifact bytes: npm install scripts
  (`preinstall`/`install`/`postinstall`) + suspicious script contents; pypi sdist
  `setup.py`/`setup.cfg`/`PKG-INFO` patterns and wheels with `setup.py` or
  executable files. Params: `mode: deny|warn` (default `deny`).
- `guarddog-scan` — the real, package-aware malware scanner: shells out to the
  **GuardDog** CLI to scan the fetched artifact bytes (npm install scripts, PyPI
  `setup.py`/wheel exec files, obfuscation, exfiltration). Runs after the fast
  `malware-scan` heuristic. Params: `mode: deny|warn` (default `deny`),
  `on_error: fail_open|fail_closed` (default `fail_open`), `timeout` (default
  60s), `sandbox: true|false` (default `true`; set `false` if Landlock is
  blocked in the container), `binary` (default `guarddog`). Malware rules update
  by bumping the pinned `guarddog` version in the Dockerfile.
- `provenance-verify` — verifies upstream provenance: **npm sigstore**
  attestations (`dist.attestations.url`) and **pypi PEP 740** attestations.
  Params: `mode: deny|warn` (default `deny`), `require_provenance: false|true`
  (default `false` — pass when no attestation is published), `on_error`
  (default `fail_open`), `identity` (regex on the signing cert SAN),
  `trust_root_dir`, `timeout`.

### Deny list

Validation failures from `{guarddog-scan, malware-scan, cve-check}` are recorded
automatically to a persistent Postgres deny list — one row per (package, version,
artifact sha256, project key, reason, middleware, timestamp). Transient
scanner/source crashes are skipped (infrastructure, not a verdict). The
`deny-list-check` middleware (auto-prepended FIRST for every request scope)
denies fast with the stored reason (403) on the next request for the same
package+hash+project, without re-running the expensive scanners. Because the
artifact sha256 is part of the key, a republished artifact is a new row.
Matching is strict per project scope: a denial blocks only the project (or
projectless traffic) that triggered it.

Config per registry under `deny_list`:

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | `false` disables recording (`deny-list-check` still runs; nothing is recorded). |
| `record_middlewares` | `[guarddog-scan, malware-scan, cve-check]` | Which validation failures are recorded as deny verdicts. |

Removal of deny-list entries is a future admin-dashboard feature.

**Retrieval** (runs on every serve, trusted and untrusted):

- `cve-check-retrieval` — re-checks OSV on every serve (including cache hits),
  closing the "CVE published after first validation" gap. **Must be first** in the
  retrieval list so it wraps the cache. Same params as `cve-check`.
- `local-disk-cache` — write-through disk cache. Params: `path`.
- `s3-cache` — write-through cache on any S3-compatible store (AWS S3, MinIO,
  GCS XML API). Params: `endpoint` (host[:port], **no scheme**), `bucket`,
  `region`, `access_key`, `secret_key`, `use_ssl`, `base_path`.
- `upstream-registry` — the terminal fetcher; always last in the chain.

**Mutation** (non-persistent view transforms re-applied on every serve):

- `strip-install-scripts` — npm only. Strips `preinstall`/`install`/`postinstall`
  from `package.json` scripts (other scripts preserved) and repacks the tarball
  deterministically. Best-effort: a tarball with no `package.json` or an invalid
  archive is served unchanged. Params: none.

> **Validation runs once per artifact.** A package is validated on first fetch
> and stored with its sha256 trust anchor; later retrievals serve the stored
> bytes without re-validating — except `cve-check-retrieval`, which re-checks on
> every serve.

> **Mutations and the trust anchor.** The stored sha256 is of the **upstream**
> bytes; a mutation (e.g. `strip-install-scripts`) rewrites the bytes served to
> the client *after* verification, deterministically, on every serve.

## Full reference

- The complete example config:
  [`config.example.yaml`](https://raw.githubusercontent.com/psenna/dependaproxy/main/config.example.yaml)
- Projects (per-project config + SBOM) and the admin API are documented in the
  [repository README](https://github.com/psenna/dependaproxy#readme).
