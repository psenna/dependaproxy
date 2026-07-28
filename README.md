# DependaProxy

DependaProxy is a secure dependency proxy that mitigates software supply-chain
attacks. Instead of letting builds download packages directly from public
registries, it validates each package through a configurable middleware
pipeline, stores a strong cryptographic hash of the validated artifact, and
later serves packages only if the served bytes match the stored hash.

> **Status:** v1 in development. v1 supports the **npm** registry, one
> validation middleware (Minimum Publication Age), one retrieval middleware
> (Local Disk Cache), YAML configuration, a PostgreSQL-backed record store, and
> an npm-compatible proxy endpoint. See the issues board for the task breakdown.

## v1 scope

- npm registry only (drop-in replacement for the default npm registry).
- Validation middleware: **Minimum Publication Age** — reject packages
  published less than N configurable days ago.
- Retrieval middleware: **Local Disk Cache** — cache validated tarballs on disk.
- YAML configuration for middleware ordering, parameters, cache location, DB.
- Database persisting: package name, version, registry, validation hash,
  validation timestamp.
- Static-token bearer auth on protected routes.
- npm-compatible proxy endpoint.

## Build & test

The host has no Go toolchain. All Go commands run inside a disposable
`golang:1.25` container against the rootless DinD daemon (see `CLAUDE.md`).
`make` handles the wiring:

```sh
make test        # go test -race -coverprofile=cover.out ./...  (in golang:1.25)
make vet         # go vet ./...
make fmt-check   # fail if gofmt would change anything
make lint        # golangci-lint run ./...
make vuln        # govulncheck ./...
make run         # go run ./cmd/dependaproxy
```

### PostgreSQL for local dev

```sh
make db          # start a postgres:18 container (localhost:5432, db=dependaproxy, pw=secret)
make stop-db     # stop it
```

Integration tests that need a database read the DSN from `DP_TEST_PG_DSN`.

## Configuration

See `config.example.yaml`. DependaProxy is configuration-driven: middleware
ordering and parameters are defined in YAML.

## Security model

The stored `validation_hash` (`sha256` of the served tarball bytes) is the
**trust anchor**. Retrieval always recomputes the hash and compares it in
constant time; a mismatch (tampered cache, corrupted disk, upstream drift) is
never served. The build is CGo-free.