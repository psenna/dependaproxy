---
layout: page
title: Development
---

{% include nav.md %}

# Development

## The Docker-in-Docker build pattern

The host has **no Go toolchain** — every Go command runs inside a disposable
`golang:1.25` container against the local Docker daemon (the Makefile handles
this transparently). Go caches live in a named volume so they persist across
runs.

## Makefile targets

```sh
make db          # start postgres:18 (db=dependaproxy, pw=secret, port 5432)
make run         # go run ./cmd/dependaproxy (uses config.yaml)
make test        # go test -race -p 1 -coverprofile=cover.out ./...
make vet         # go vet ./...
make fmt-check   # fail on gofmt drift
make lint        # golangci-lint
make vuln        # govulncheck
make tidy        # go mod tidy
make minio       # start a local minio/minio server for the S3-cache tests
make stop-db     # stop postgres
make stop-minio  # stop minio
make clean       # remove cover.out / cover.html
make all         # vet + fmt-check + test
```

`make test` runs with `-p 1` to serialize the shared-DB integration tests. The
build is CGo-free except the race detector.

## Integration tests

Tests that need PostgreSQL read `DP_TEST_PG_DSN` and **skip when it is unset**
(CI sets it against a `postgres:18` service):

```sh
export DP_TEST_PG_DSN='postgres://postgres:secret@localhost:5432/dependaproxy?sslmode=disable'
make test
```

S3-cache integration tests read `DP_TEST_MINIO_ENDPOINT` /
`DP_TEST_MINIO_ACCESS_KEY` / `DP_TEST_MINIO_SECRET_KEY` and skip when unset
(`make minio` starts a local server; CI runs them against a real `minio/minio`).

## CI

The `.github/workflows/ci.yml` workflow runs on push to `main`/`feat/*` and PRs
to `main`: `go vet`, gofmt check, `golangci-lint`, `govulncheck`, the full race
test suite against `postgres:18`, and the S3-cache tests against a real MinIO
container. The `release.yml` workflow builds the Docker image and publishes it to
GHCR (`ghcr.io/psenna/dependaproxy:<release-tag>`) on every GitHub Release cut
from `main`.

## Extending

- **New registry** = one package under `internal/registry/<x>` + one
  `adapter.Register` call; the shared core never changes.
- **New middleware** = one file + one config entry (register a factory in the
  adapters; see the `cve-check`, `malware-scan`, and `strip-install-scripts`
  implementations for the validation / retrieval / mutation patterns).
- **New project config via the admin API** — projects are runtime-managed through
  `POST/GET/PUT/DELETE /admin/projects` (see [Examples](examples) #5).

The full architecture, adapter contracts, and middleware semantics are in the
[repository README](https://github.com/psenna/dependaproxy#readme).
