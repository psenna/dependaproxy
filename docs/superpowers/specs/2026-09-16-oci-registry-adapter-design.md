# OCI/container-registry adapter — design

## Context

DependaProxy mediates and supply-chain-validates npm/PyPI/Go dependency
fetches today (`type: npm|pypi|goproxy`). It has no equivalent for
`docker pull`/`docker run` — a client with network access to a registry can
pull any image, unrestricted. [ai-sandbox](https://github.com/psenna/ai-sandbox)
worked around this on the client side with a host-level iptables allowlist
(restricts *which registry host* is reachable), but that mechanism can't
restrict *which image or tag*, verify digests, or cache anything — iptables
has no visibility into HTTP request content. See
[psenna/dependaproxy#189](https://github.com/psenna/dependaproxy/issues/189)
for the originating feature request and initial architecture survey this
design builds on.

This spec covers a new `type: oci` registry adapter: a pull-through proxy for
the Docker Registry HTTP API v2 / OCI Distribution spec, with a wildcard
path-allowlist validation middleware and support for routing to multiple
upstream registries from one DependaProxy instance.

## Decisions carried in from brainstorming

- **v1 scope: no caching.** Validate, then reverse-proxy to upstream on every
  request. No local disk cache, no digest-keyed blob store. Caching is a
  well-isolated follow-up once the request/response plumbing is proven.
- **Multi-registry routing: uniform explicit-prefix addressing for every
  registry**, including Docker Hub — no special-cased transparent
  `registry-mirrors` behavior for Hub. One consistent addressing scheme to
  document and reason about.
- **Allowlist scope: per upstream**, not global — mirrors how every other
  validation middleware (`cve-check`, `malware-scan`) is already scoped to
  one registry's config, not shared instance-wide.
- **Implementation: use `github.com/google/go-containerregistry`** for the
  upstream-fetching side (its `remote` package already handles the
  per-registry Bearer-auth handshake quirks: Docker Hub, GHCR, Quay, private
  registries). We hand-roll our own server-side routes and keep our own
  validation pipeline in front of every fetch — only "talk correctly to an
  arbitrary upstream registry" is outsourced.

## The routing constraint that shapes everything else

The Docker Registry v2 / OCI Distribution spec fixes the request path at
`/v2/<repository-name>/manifests|blobs/<reference>` under a **single**
registry host authority — a client always resolves "which registry" from the
host:port of the image reference, then always calls `/v2/...` on that one
authority. There is no URL-prefix-based multi-tenancy at the protocol level
the way `/npm`, `/pypi`, `/goproxy` give DependaProxy today.

So `dependaproxy:8080/docker/library/nginx:latest` arrives on the wire as:

```
GET /v2/docker/library/nginx/manifests/latest
Host: dependaproxy:8080
```

— `docker/library/nginx` is the full "repository name" as far as the Docker
client and the registry-v2 protocol are concerned. The "which upstream"
selector can only live as a **leading path segment inside the repository
name**, not as a separate prefix before a nested `/v2/`. This is the same
pattern Artifactory, Harbor, and GitLab's dependency proxy use for exactly
this reason — not a DependaProxy-specific workaround.

**Consequence:** one `oci` adapter instance, mounted once at the fixed prefix
`/v2` (not one adapter instance per upstream like npm/pypi/goproxy). It must
answer a bare `GET /v2/` ping with `200` unconditionally — Docker's client
always probes this once per registry *host*, before any specific pull, so it
cannot be tied to a specific upstream.

## Config shape

`RegistryConfig` gains one new field, populated only for `type: oci`:

```go
// Upstreams is OCI-only: the named upstream registries this single
// /v2-mounted adapter instance routes between, keyed by the leading path
// segment of the repository name a client requests. Every other adapter
// type has exactly one Upstream (the existing flat field) and leaves this
// nil.
Upstreams []OCIUpstreamConfig `yaml:"upstreams"`
```

```go
// OCIUpstreamConfig is one named upstream registry an oci adapter instance
// routes to. Name is the path segment a client selects it with
// (dependaproxy:8080/<name>/<repo>:<tag>) — must be a valid single Docker
// repository-name path segment (lowercase alnum + separators), since it
// becomes part of the "repository name" the Docker client itself parses.
type OCIUpstreamConfig struct {
    Name                 string       `yaml:"name"`
    Upstream             string       `yaml:"upstream"` // e.g. https://registry-1.docker.io
    AllowedUpstreamHosts []string     `yaml:"allowed_upstream_hosts"` // auth/blob-CDN hosts, same SSRF-allowlist purpose as the existing field
    Validation           []Middleware `yaml:"validation"`
}
```

Example `dependaproxy.yaml` fragment:

```yaml
registries:
  - type: oci
    prefix: /v2   # fixed: the registry-v2 spec requires this exact root
    upstreams:
      - name: docker
        upstream: https://registry-1.docker.io
        allowed_upstream_hosts:
          - auth.docker.io
          - production.cloudflare.docker.com
        validation:
          - type: path-allowlist
            params:
              patterns: ["library/*", "bitnami/*"]
      - name: ghcr
        upstream: https://ghcr.io
        allowed_upstream_hosts:
          - pkg-containers.githubusercontent.com
        validation:
          - type: path-allowlist
            params:
              patterns: ["psenna/*"]
```

A client pulls `docker.io/library/nginx:latest` as
`dependaproxy:8080/docker/library/nginx:latest`, and
`ghcr.io/psenna/ai-sandbox-agent:latest` as
`dependaproxy:8080/ghcr/psenna/ai-sandbox-agent:latest`.

**Validation**: `prefix` for a `type: oci` entry must be exactly `/v2`
(reject at config-load time otherwise — a different prefix cannot work,
per the routing constraint above); `Upstreams` must be non-empty with unique
`Name`s, each a valid single path segment. A `type: oci` entry ignores the
existing flat `Upstream`/`AllowedUpstreamHosts`/`UpstreamAlias` fields
entirely (those are meaningless without a single upstream) — only
`Upstreams[]` is read. At most one `type: oci` entry can exist per instance
(two would both need to claim `/v2`), but this needs no new check: the
existing `registries[i]: duplicate prefix` validation (`config.go:152`)
already rejects two entries sharing a prefix.

## Path-allowlist validation middleware

New package `internal/middleware/validation/pathallowlist/`, registered as
`type: path-allowlist` alongside the existing `cve-check`/`malware-scan`/
`guarddog-scan` validation middlewares — same `ValidationMiddleware`
interface (`Name() string`, `Validate(ctx *pipeline.PipelineContext) error`),
so it is usable by *any* adapter, not only `oci` (a future registry type
could reuse it unchanged).

```yaml
- type: path-allowlist
  params:
    patterns: ["library/*", "bitnami/*"]   # glob, matched against ctx.PkgName
```

- Matches `ctx.PkgName` (for `oci`, the repository name with the upstream
  selector already stripped, e.g. `library/nginx`) against each pattern with
  Go's stdlib `path.Match` (`*` matches within one path segment, same
  semantics as shell glob) — no new dependency needed for this.
- Denies (`ValidationError`, mapped to the registry-v2 `DENIED` code) if no
  pattern matches. An empty `patterns` list is a config error (denies
  everything, almost certainly not intended) rather than a silent
  allow-all — `Factory` rejects it at config-load time.
- Runs first in each upstream's `validation:` chain, before any upstream
  network call — a denied pull never reaches go-containerregistry.

## Request flow

1. `GET /v2/` → `200`, header `Docker-Distribution-API-Version: registry/2.0`,
   body `{}`. Unconditional — does not touch any upstream.
2. `GET|HEAD /v2/<name>/manifests/<ref>`, `GET /v2/<name>/blobs/<digest>`:
   - Split `<name>` on the first `/` into `upstreamName`, `repoPath`. Unknown
     `upstreamName` → `404` with the registry-v2 `NAME_UNKNOWN` error
     envelope (`{"errors":[{"code":"NAME_UNKNOWN","message":"..."}]}`).
   - Build a `PipelineContext{Registry: "oci/" + upstreamName, PkgName:
     repoPath, Version: ref}` and run that upstream's validation chain.
     Failure → `403` with `DENIED`.
   - On pass: use go-containerregistry's `remote` package
     (`remote.Get`/`remote.Layer`) against `<upstream.Upstream>/<repoPath>`
     to fetch the manifest or blob. `remote` handles the Bearer-auth
     challenge/token exchange per upstream internally.
   - Stream the response back with the correct `Content-Type` and
     `Docker-Content-Digest` headers. For a tag-based manifest fetch,
     `Docker-Content-Digest` is the digest **computed from the returned
     bytes** (`v1.Manifest.Digest()`, part of go-containerregistry's own
     decode path) — never trusted verbatim from the upstream response, so an
     upstream cannot lie about what it served.
   - Upstream `404`/network error → map to `BLOB_UNKNOWN`/`MANIFEST_UNKNOWN`
     as appropriate, not a bare 500.
3. v1 targets **public upstream registries only** — `remote` is called with
   an anonymous authenticator. Private-registry credential passthrough is
   explicitly out of scope for v1 (no operator-configured per-upstream
   credentials yet).

## Error envelope

The registry-v2 spec requires a specific JSON body on error responses so the
Docker client can render a real message instead of "unknown error":

```json
{"errors": [{"code": "DENIED", "message": "...", "detail": {}}]}
```

New `internal/registry/oci/errors.go` maps internal failures to the relevant
codes (`NAME_UNKNOWN`, `MANIFEST_UNKNOWN`, `BLOB_UNKNOWN`, `DENIED`,
`UNAUTHORIZED`) — same spirit as `internal/api/errors.go`-style mapping
files elsewhere in the codebase, scoped to this adapter.

## Testing

- Unit tests for `path-allowlist`: pattern matching (single-segment glob,
  multiple patterns, no match, malformed pattern at config-load).
- Unit tests for upstream-name routing: known/unknown `name`, path splitting,
  the fixed `/v2` prefix validation at config load.
- `GET /v2/` ping test — must not touch any upstream (verify via a
  request-count assertion on a fake upstream).
- Live-network e2e test (build-tag gated, mirroring `goproxy/e2e_test.go`'s
  existing pattern): pull a tiny public image's manifest+one blob through a
  real upstream (e.g. a small `ghcr.io` image) to prove the
  go-containerregistry integration and digest verification actually work
  end-to-end, not just against a mock.
- Denylist/audit integration: confirm a `path-allowlist` denial is recorded
  the same way an existing validation denial is (existing `DenyListConfig`
  machinery, `RecordMiddlewares` defaulting).

## Explicitly out of scope for v1

- Any caching (local-disk or otherwise) — a follow-up once this is proven.
- Private-upstream credentials / authenticated pulls.
- Push support — pull-through only.
- Image-content vulnerability/malware scanning (needs new middleware
  operating on assembled image layers, e.g. Trivy/Grype-style — `cve-check`
  and `malware-scan` as they exist today have no notion of a container image
  and do not apply here).
- Multi-arch manifest-list handling beyond basic pass-through (an index
  manifest is proxied as-is; no per-platform filtering).

## Downstream follow-up (not part of this repo's implementation)

Once this ships, ai-sandbox's `dind-init.sh` registry allowlist and
`AGENT_IMAGE`/image-reference conventions would need updating to address
images via `dependaproxy:8080/<name>/<repo>:<tag>` instead of (or alongside)
the current host-level iptables allowlist. Tracked separately in that repo,
not part of this design.
