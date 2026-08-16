# dependaproxy

A Helm chart for [dependaproxy](https://github.com/psenna/dependaproxy) -- a
validating pull-through proxy for npm/PyPI/Go module registries (deny-list,
CVE, malware, and GuardDog checks on every package before it reaches your
build).

## Quick start

The production-recommended path points dependaproxy at an external / managed
PostgreSQL instance (`postgresql.enabled: false`, the default). dependaproxy
has exactly one config input -- a single `-config /path/to/config.yaml` flag,
no environment-variable overrides -- so the two secrets below are required
before the chart will even render (see
["Secrets & the fragment-assembly mechanism"](#secrets--the-fragment-assembly-mechanism)
for why).

```sh
# 1. Create the required Secrets from the copy-pasteable examples.
#    Edit the CHANGE-ME placeholders first.
kubectl apply -f examples/auth-secret.yaml
kubectl apply -f examples/storage-secret.yaml

# 2. Install, pointing at those Secrets.
helm install my-dependaproxy . \
  --set auth.existingSecret=dependaproxy-auth \
  --set storage.existingSecret=dependaproxy-storage
```

By default this installs with `config.registries` set to a sane npm + PyPI
configuration (deny-list, min publication age, CVE check, malware scan,
GuardDog scan, and a per-pod local-disk cache) and `ingress.enabled: false`
(reach the Service with `kubectl port-forward`, printed in the post-install
NOTES).

## Bundled PostgreSQL (dev only)

```
==============================================================================
DEV / DEMO ONLY -- NOT FOR PRODUCTION
------------------------------------------------------------------------------
A single-instance, hand-rolled PostgreSQL. No HA, no replication, no
backups, no restore, no PITR, no connection pooling, no TLS, no upgrade path
between major versions. Losing this pod's PVC loses your entire deny list,
project configs, and dependency/SBOM records -- dependaproxy keeps ALL
authoritative state here.

For production: leave postgresql.enabled=false and point storage.existingSecret
at a managed / HA PostgreSQL instead.
==============================================================================
```

Set `postgresql.enabled: true` and leave `storage.existingSecret` empty; the
chart bundles its own single-replica Postgres StatefulSet and generates a
matching `storage:` Secret for you (`templates/postgresql/secret.yaml`).
`auth.existingSecret` is still required -- it is never auto-generated.

A few sharp edges specific to this path:

- **`lookup` and dry-run commands.** The generated Secret preserves its
  Postgres password across `helm upgrade` by looking up the *previous*
  Secret in the cluster and reusing its password if present (the same idiom
  well-known charts such as Bitnami's use). `lookup` returns `nil` during
  `helm template`, `helm install --dry-run`, and `helm diff` -- none of those
  commands can see cluster state -- so each such run generates a **fresh
  random password**. Never diff-compare this Secret's rendered content
  between runs; it is expected to differ every time under those commands
  even when nothing changed in the cluster.
- **`helm rollback` stale-password hazard.** Rolling back to a revision from
  *before* this Secret was first generated restores that old revision's
  manifest, which may carry a stale password, while the PostgreSQL data
  volume keeps whatever the *current* password actually is. If that
  happens, recover by either:
  - `kubectl exec` into the postgresql pod and run
    `ALTER USER <user> PASSWORD '<current-password>';` to reconcile the
    database to match the rolled-back Secret, or
  - `kubectl delete pvc <release>-dependaproxy-postgresql-data-...` plus a
    fresh install, if the existing data can be discarded.
- **Immutable PVC size.** `postgresql.persistence.size` feeds a
  StatefulSet's `volumeClaimTemplates`, which Kubernetes treats as
  immutable after creation. `helm upgrade --set postgresql.persistence.size=...`
  will not resize an existing volume -- you must resize the underlying PVC
  out-of-band (if your StorageClass supports online expansion) or migrate
  to a new PVC.

## Secrets & the fragment-assembly mechanism

**Why:** dependaproxy takes exactly one input, `-config /path/to/config.yaml`,
and has no environment-variable override path for any setting. That means
every secret the app needs (admin token, package-fetch token, database DSN,
and optionally s3-cache credentials) has to live *inside* that one assembled
YAML file -- there's nowhere else to put it. Rather than rendering secrets
into a ConfigMap (plaintext in `kubectl get configmap -o yaml` and in
`helm get manifest`), the chart mounts each secret fragment from its own
Secret and assembles them at pod startup.

**How:** an `assemble-config` init container concatenates a base fragment
(rendered from values, containing `server:`, `log:`, and optionally
`registries:`) with one or more Secret-sourced fragments into
`/run/dependaproxy/config.yaml`, which is what the container actually reads
via `-config`.

| Fragment | Values field(s) | Default Secret key | Mounted at |
|---|---|---|---|
| base (`server`, `log`, and `registries` unless sourced from a Secret) | `config.server`, `config.log`, `config.registries` | n/a (ConfigMap) | `/etc/dependaproxy/base/config.yaml` |
| auth | `auth.existingSecret`, `auth.key` | `auth.yaml` | `/etc/dependaproxy/fragments/10-auth/auth.yaml` |
| storage | `storage.existingSecret`, `storage.key` (or the chart's own generated Secret when `postgresql.enabled: true`) | `storage.yaml` | `/etc/dependaproxy/fragments/20-storage/storage.yaml` |
| registries (optional) | `config.registriesExistingSecret`, `config.registriesKey` | `registries.yaml` | `/etc/dependaproxy/fragments/30-registries/registries.yaml` |
| extra (optional, repeatable) | `extraConfigFragments[].existingSecret`, `extraConfigFragments[].key` | n/a (required per entry) | `/etc/dependaproxy/fragments/90-extra-<index>/<key>` |

Fragments are concatenated verbatim in that order, not deep-merged --
a top-level YAML key that appears in two fragments is a duplicate-mapping-key
parse error and the pod crash-loops on `assemble-config` (the init container
also fails fast if the assembled file is missing a `storage:`, `auth:`, or
`registries:` block).

**Rollout behavior:** the Deployment carries a `checksum/config` pod
annotation derived from the rendered ConfigMap and from the *names/keys* of
every referenced Secret, so changing which Secret/key a values field points
at triggers an automatic rolling restart. It does **not** hash Secret
*contents* (the chart never reads them at render time) -- rotating a
Secret's data in place (e.g. `kubectl create secret ... --dry-run=client -o
yaml | kubectl apply -f -`) is invisible to that checksum. After rotating any
Secret's content, run:

```sh
kubectl rollout restart deployment/<release>-dependaproxy
```

## Using s3-cache (registries from a Secret)

`local-disk-cache` (the default retrieval middleware) writes to each pod's
own ephemeral/PVC-backed disk. To use the `s3-cache` retrieval middleware
instead, its `access_key`/`secret_key` params have to live somewhere other
than plaintext values.yaml -- so the chart supports sourcing the *entire*
`registries:` block from a Secret. See
[`examples/registries-secret.yaml`](examples/registries-secret.yaml) for a
full example (npm + PyPI, each with an `s3-cache` retrieval step using
`endpoint`, `bucket`, `region`, `access_key`, `secret_key`, `use_ssl`, and
`base_path`).

To use it:

```yaml
config:
  registries: []
  registriesExistingSecret: dependaproxy-registries
  registriesKey: registries.yaml   # only if you used a different key name
```

`config.registriesExistingSecret` and `config.registries` are **mutually
exclusive** -- the chart's render-time validation (`dependaproxy.validate` in
`templates/_helpers.tpl`) fails the render if both are set, because two
top-level `registries:` keys in the assembled config.yaml would otherwise be
a duplicate-mapping-key parse error dependaproxy would only discover at
startup.

## Ingress

Set `ingress.enabled: true` and configure `ingress.className`,
`ingress.hosts`, and `ingress.tls` as needed. A copy-paste nginx annotation
block that matches dependaproxy's actual traffic shape:

```yaml
nginx.ingress.kubernetes.io/proxy-buffering: "off"
nginx.ingress.kubernetes.io/proxy-body-size: "0"
nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
nginx.ingress.kubernetes.io/proxy-connect-timeout: "10"
```

- `proxy-buffering: "off"` and `proxy-body-size: "0"`: large package
  tarballs stream through the proxy; buffering the whole response (or
  capping the body size) breaks or stalls big downloads.
- `proxy-read-timeout` / `proxy-send-timeout: "600"`: a cold fetch runs the
  entire validation pipeline (upstream fetch, CVE check, malware scan,
  GuardDog scan with a default 60s timeout, optional sigstore verification)
  before the first response byte is written -- this matches the app's own
  10-minute `http.Server.WriteTimeout`, so the ingress read/send timeouts
  need to be at least that generous or the ingress controller will cut the
  connection before the app does.
- `proxy-connect-timeout: "10"`: fine at the default; the backend Service is
  in-cluster.

Equivalent settings on other ingress controllers:

| Concern | nginx | Traefik | HAProxy (ingress) |
|---|---|---|---|
| Disable response buffering | `proxy-buffering: "off"` | `traefik.ingress.kubernetes.io/router.middlewares` referencing a `buffering` middleware with `maxRequestBodyBytes`/`maxResponseBodyBytes` unset | `haproxy.org/response-buffering` (or omit; HAProxy streams by default) |
| Uncap body size | `proxy-body-size: "0"` | omit `maxRequestBodyBytes` on the buffering middleware (unset = unbounded) | `haproxy.org/max-connections` is unrelated; there's no per-request cap to set |
| Read/send timeout | `proxy-read-timeout`, `proxy-send-timeout: "600"` | `traefik.ingress.kubernetes.io/router.middlewares` referencing a `forwardauth`/`headers` timeout config, or set on the entrypoint's `transport.respondingTimeouts` | `haproxy.org/timeout-server`, `haproxy.org/timeout-client: "600s"` |

**Security note:** `/` (the dashboard SPA shell) and `/healthz` are
unauthenticated by the app itself; only `/admin/*` and the registry prefixes
(`/npm`, `/pypi`, ...) are token-gated. Do not expose this Ingress publicly
with `auth.token` left empty -- an empty `auth.token` disables package-fetch
auth entirely and is documented as a local-dev-only convenience.

## Multi-replica

`replicaCount > 1` is fully supported -- all authoritative state
(deny list, project configs, dependency/SBOM records) lives in PostgreSQL,
not in any pod. The one caveat is the artifact cache: with the default
per-pod `local-disk-cache`, each replica has its own independent cache, so
the effective hit rate degrades roughly 1/N across N replicas. If you need a
cache that's actually shared across replicas, switch to the `s3-cache`
retrieval middleware (see
["Using s3-cache"](#using-s3-cache-registries-from-a-secret) above) instead
of relying on `persistence.cache`.

If you enable `persistence.cache.enabled: true` (a single `ReadWriteOnce`
PVC by default) together with `replicaCount > 1`, the chart refuses to
render: a `ReadWriteOnce` volume can only be attached on one node at a time,
so replicas scheduled elsewhere would hang `Pending` on
`FailedAttachVolume` -- a silent, hard-to-diagnose rollout stall the chart
catches at template time instead. The failure message
(`dependaproxy.validateCacheReplicas` in `templates/_helpers.tpl`) lists the
fix options: drop to `replicaCount: 1`; use `persistence.cache.accessModes:
[ReadWriteMany]` on an RWX StorageClass; point `persistence.cache.existingClaim`
at an existing RWX claim; disable `persistence.cache` and use `s3-cache`
instead; or set `persistence.cache.ignoreAccessModeCheck: true` if every
replica is pinned to one node.

## GuardDog & readOnlyRootFilesystem

The chart defaults `securityContext.readOnlyRootFilesystem: true` -- a
supply-chain security tool should itself satisfy the Kubernetes *restricted*
Pod Security Standard by default, not require a wide-open write filesystem
to run.

GuardDog, however, writes resource files (e.g. `top_npm_packages.json`)
inside its own installed `site-packages` at runtime, which under a read-only
root filesystem would otherwise fail. The chart works around this with a
`copy-guarddog-venv` init container: it copies the image's baked-in
`/opt/guarddog-venv` onto an `emptyDir` volume that's then mounted back over
the *identical* path (`guarddog.writableVenv.path`) in the main container --
GuardDog gets a writable copy of its own venv without the rest of the
filesystem being writable.

The main container also gets explicit `HOME=/home/dependaproxy` and
`TMPDIR=/tmp` environment variables (both backed by their own `emptyDir`
mounts). The image's container process runs as the bare numeric uid `65532`
with no corresponding `/etc/passwd` entry, so without an explicit `$HOME`
it would resolve to `/`, which is unwritable under
`readOnlyRootFilesystem: true`. This isn't just cosmetic: an unwritable
`$HOME` specifically breaks the `provenance-verify` middleware, which caches
its sigstore trust root under `$HOME`.

If your deployment never uses `guarddog-scan` -- neither statically in
`config.registries`/the registries Secret, nor via a runtime admin-API
project override -- you can turn the whole mechanism off with:

```yaml
guarddog:
  writableVenv:
    enabled: false
```

(see `ci/no-guarddog-values.yaml` for a working fixture).

## Secret rotation

The Deployment's `checksum/config` annotation only reacts to changes in
values-driven config (the rendered ConfigMap, and which Secret name/key each
values field points at) -- it cannot hash content the chart never reads.
After rotating the *content* of any Secret (not just re-pointing a values
field at a differently-named Secret), trigger the rollout yourself:

```sh
kubectl rollout restart deployment/<release>-dependaproxy
```

## Values reference

Not exhaustive -- `values.yaml` is heavily commented in place; read it for
the full set. The most important fields:

| Key | Purpose |
|---|---|
| `auth.existingSecret` | Secret holding the `auth:` fragment (`auth.token` + `auth.admin_token`). Required, no default. |
| `storage.existingSecret` | Secret holding the `storage:` fragment (Postgres DSN). Required unless `postgresql.enabled: true`. |
| `postgresql.enabled` | Bundle a single-instance DEV/DEMO-ONLY PostgreSQL instead of using an external one. |
| `config.registries` | The `registries:` block templated from values (mutually exclusive with `config.registriesExistingSecret`). |
| `config.registriesExistingSecret` | Source the whole `registries:` block from a Secret instead (required for s3-cache credentials). |
| `cache.mountPath` | The one writable cache mount `local-disk-cache` paths must live under. |
| `persistence.cache.enabled` | Back the cache mount with a PVC instead of an `emptyDir`. See the multi-replica caveat above. |
| `ingress.enabled` | Render an Ingress for the Service. |
| `replicaCount` | Deployment replica count. Fully supported >1; see "Multi-replica" above. |
| `image.tag` | Image tag; falls back to `Chart.AppVersion` when empty (there is no `:latest` tag published). |
