---
layout: page
title: Getting Started
---

{% include nav.md %}

# Getting Started

This guide runs a DependaProxy instance and points `npm` and `pip` at it. There
are two ways to run it: **from source** (Docker-in-Docker, for development) or
**from the published Docker image** (for a deployment).

## Prerequisites

- **Docker** — the only hard requirement. The host needs **no Go toolchain**:
  the Makefile runs every Go command inside a disposable `golang:1.25` container
  against the local Docker daemon.
- **PostgreSQL** for the trust-anchor storage (the proxy will not serve without
  its backing store). `make db` starts a `postgres:18` container with
  `db=dependaproxy`, `pw=secret`, on port `5432`.

## 1. Create a config

Copy the example and edit it — at minimum the `auth.token` and the `storage.dsn`:

```sh
cp config.example.yaml config.yaml
# config.yaml: set auth.token to a real bearer token, and point storage.dsn at
# your Postgres (make db gives postgres://postgres:secret@localhost:5432/dependaproxy?sslmode=disable)
```

> The example already configures the npm + pypi registries with
> `min-publication-age`, `cve-check`, `malware-scan`, `cve-check-retrieval`,
> and local-disk caches. `provenance-verify` and `strip-install-scripts` are
> present but commented out — uncomment to enable.

## 2a. Run from source (development)

```sh
make db                 # postgres:18 (db=dependaproxy, pw=secret, port 5432)
make run                # go run ./cmd/dependaproxy — uses config.yaml
```

Wait for the health check to answer:

```sh
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## 2b. Run the published Docker image (deployment)

The `release.yml` workflow builds the image on every GitHub Release and publishes
it to GHCR. **There is no `latest` tag — use the release tag** (e.g. the latest
from the [Releases](https://github.com/psenna/dependaproxy/releases) page).

The image expects the config mounted at `/config.yaml` (`CMD ["-config",
"/config.yaml"]`), runs as uid 65532, and listens on 8080:

```sh
docker run -d --name dependaproxy \
  -p 8080:8080 \
  -v "$PWD/config.yaml:/config.yaml:ro" \
  ghcr.io/psenna/dependaproxy:<tag>        # e.g. :v1.0.0

curl http://localhost:8080/healthz
# {"status":"ok"}
```

> The image is `scratch`-based (CGo-free); the CA bundle is baked in so outbound
> calls to `registry.npmjs.org` / `pypi.org` work. Because it runs as uid 65532,
> give your config file and cache directories appropriate ownership.

## 3. Point your package managers at it

With `auth.token` set, configure the credential once, then install normally:

```sh
# npm
npm config set //localhost:8080/:_authToken <token>
npm install --registry http://localhost:8080/npm <pkg>

# pip
pip config set global.index-url http://user:<token>@localhost:8080/pypi/simple
pip download <pkg>
```

If `auth.token` is empty (local dev only), omit the credential lines.

## Next steps

- [Examples](examples) — end-to-end copy-paste blocks, including projects +
  SBOM and a gate in action.
- [Configuration](configuration) — every config field and middleware type.
- The [repository README](https://github.com/psenna/dependaproxy#readme) for the
  full reference.
