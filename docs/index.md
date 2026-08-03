---
layout: home
title: DependaProxy
---

{% include nav.md %}

# DependaProxy

**DependaProxy is a secure dependency proxy that mitigates software supply-chain
attacks.** Instead of letting builds download packages directly from public
registries, it validates each package through a configurable middleware pipeline,
stores a strong cryptographic hash of the validated artifact, and later serves
packages only if the served bytes match the stored hash. If an artifact is ever
tampered with in the cache, the mismatch is caught, the entry is evicted and
refetched, and the corrupted bytes are never served.

**v2 is multi-registry:** one instance serves several registries at the same
time, segregated by URL path prefix (`/npm/…`, `/pypi/…`, `/maven/…`), via a
shared core + per-registry **adapter** plugins. Clients point their package
manager at the proxy with no client-side changes beyond the registry/index URL.

## What it does

- **Validates before it trusts** — every package runs a configurable middleware
  chain (`min-publication-age`, `cve-check` against OSV.dev, `malware-scan`,
  `provenance-verify`) before its sha256 trust anchor is stored.
- **Serves only verified bytes** — every retrieval re-verifies the sha256 in
  constant time; a mismatch is never served.
- **Re-checks over time** — `cve-check-retrieval` re-queries OSV.dev on *every*
  serve, so a CVE published *after* first validation still blocks the next
  install.
- **Remediates, not just detects** — the `strip-install-scripts` mutator removes
  npm install-script attack vectors from the bytes served to the client.
- **Per-project configuration + SBOM** — a consuming codebase can pass a project
  key (`/npm/p/<key>`) to get its own middleware config, and DependaProxy records
  every package@version it downloads as a per-project SBOM.
- **Supply-chain-safe npm** — npm traffic flows through the proxy; the public
  registries are network-blocked from workload containers.

## Run it in 60 seconds

```sh
cp config.example.yaml config.yaml      # edit auth.token + storage.dsn
make db                                  # postgres:18 (db=dependaproxy, pw=secret)
make run                                 # go run ./cmd/dependaproxy — uses config.yaml
curl http://localhost:8080/healthz       # {"status":"ok"}
npm install --registry http://localhost:8080/npm lodash
```

See [Getting Started](getting-started) for the full run guide — from source, from
the published Docker image, and pointing `npm`/`pip` at the proxy. See
[Examples](examples) for end-to-end copy-paste examples including projects + SBOM.

## Adapters

| Adapter | Prefix | Status |
|---|---|---|
| npm | `/npm` | packument + tarball, `dist.tarball` rewrite, `(name, version)` store |
| pypi | `/pypi` | PEP 691 JSON index, per-file store with platform/python/abi tags |
| maven | `/maven` | skeleton (returns 501); full routing/storage is a future issue |

## Documentation

- [Getting Started](getting-started) — prerequisites, run from source, run the
  published Docker image, point `npm`/`pip` at it.
- [Examples](examples) — end-to-end copy-paste: installs, projects CRUD + SBOM,
  a gate in action.
- [Configuration](configuration) — config fields, registries, and middleware
  types by stage.
- [Development](development) — Makefile targets, the Docker-in-Docker build
  pattern, and the gated integration tests.

The full project reference lives in the [repository README](https://github.com/psenna/dependaproxy#readme).
