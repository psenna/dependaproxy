---
layout: page
title: Kubernetes (Helm)
---

{% include nav.md %}

# Kubernetes (Helm)

A Helm chart runs dependaproxy on Kubernetes. It supports the same
npm/PyPI/Go module validation and retrieval pipeline as running it from
source or the Docker image, plus a Deployment, Service, optional Ingress, and
optional bundled PostgreSQL for quick evaluation.

## Prerequisites

- A Kubernetes cluster.
- Helm 3.8+ (needed for OCI registry support — the chart is published to
  GHCR, not a traditional chart repository).

## Install

```sh
helm install dependaproxy oci://ghcr.io/psenna/charts/dependaproxy --version <chart-version>
```

There is no `:latest` — pick a published chart version (see the [Releases
page](https://github.com/psenna/dependaproxy/releases) or the [GHCR package
page](https://github.com/psenna/dependaproxy/pkgs/container/charts%2Fdependaproxy)
for what's published).

## Storage: bundled vs. external PostgreSQL

The chart supports two mutually exclusive storage paths:

- **Bundled PostgreSQL** (`postgresql.enabled: true`) — a single-instance,
  DEV/DEMO-ONLY Postgres the chart manages for you. No separate database to
  provision, but no HA, backups, or tuning.
- **External / managed PostgreSQL** (`storage.existingSecret: <secret>`,
  the default) — you point the chart at a Secret holding the DSN for your
  own (ideally managed) Postgres instance.

Use external Postgres for anything beyond a demo.

## Creating the required Secrets

dependaproxy has exactly one config input and no environment-variable
overrides, so `auth.existingSecret` and (for external Postgres)
`storage.existingSecret` must exist before the chart will render. Copy-paste
starting points for these Secrets live in
[`deploy/helm/dependaproxy/examples/`](https://github.com/psenna/dependaproxy/tree/main/deploy/helm/dependaproxy/examples)
in the repo — edit the `CHANGE-ME` placeholders and `kubectl apply` them.

## Using s3-cache (registries from a Secret)

The `s3-cache` retrieval middleware needs `access_key`/`secret_key`, which
should not live in plain `values.yaml`. Set `config.registriesExistingSecret`
to a Secret holding the whole `registries:` block instead of
`config.registries` — see
[`examples/registries-secret.yaml`](https://github.com/psenna/dependaproxy/tree/main/deploy/helm/dependaproxy/examples/registries-secret.yaml).

## Ingress

Large package downloads need proxy buffering disabled, a raised body-size
limit, and generous timeouts, or big tarballs/wheels will fail partway
through. The chart's README has the full recommended annotation block for
ingress-nginx — see [Ingress in the chart
README](https://github.com/psenna/dependaproxy/tree/main/deploy/helm/dependaproxy#ingress).

## Post-install smoke test

```sh
helm test <release>
```

## Full reference

The chart README covers the complete install flow, values reference, secret
rotation, multi-replica caching, and GuardDog/`readOnlyRootFilesystem`
notes: [dependaproxy Helm chart
README](https://github.com/psenna/dependaproxy/tree/main/deploy/helm/dependaproxy).
