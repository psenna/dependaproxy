---
layout: page
title: Examples
---

{% include nav.md %}

# Examples

Copy-paste end-to-end examples. `$TOKEN` below is the `auth.token` from your
config.

## 1. Run from source

```sh
cp config.example.yaml config.yaml
make db
make run                      # uses config.yaml
curl http://localhost:8080/healthz   # {"status":"ok"}
```

## 2. Run the published Docker image

```sh
docker run -d --name dependaproxy -p 8080:8080 \
  -v "$PWD/config.yaml:/config.yaml:ro" \
  ghcr.io/psenna/dependaproxy:<tag>     # a release tag — there is no :latest
```

## 3. Install an npm package through the proxy

```sh
npm install --registry http://localhost:8080/npm lodash
# or with auth:
npm config set //localhost:8080/:_authToken $TOKEN
npm install --registry http://localhost:8080/npm lodash
```

## 4. Download a Python package through the proxy

```sh
pip download --index-url http://localhost:8080/pypi/simple requests
# or with auth:
pip config set global.index-url http://user:$TOKEN@localhost:8080/pypi/simple
pip download requests
```

## 5. Per-project config + SBOM

Create a project `acme` whose npm `cve-check` **warns** (while the global default
is `deny`):

```sh
curl -fsS -X POST http://localhost:8080/admin/projects \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"mode":"warn"}}]}}}'
```

Install a package through the project pipeline. Request the **project-scoped
tarball URL directly** so the download is validated under `acme`'s config and
recorded in `acme`'s SBOM:

```sh
curl -fsS http://localhost:8080/npm/p/acme/<pkg>/-/<version>.tgz \
  -H "Authorization: Bearer $TOKEN" -o <pkg>-<version>.tgz
```

> Setting `npm install --registry http://localhost:8080/npm/p/acme` fetches the
> packument project-scoped, but until the URL-rewrite follow-up lands, npm
> follows the rewritten `dist.tarball` URL back to the default path — so the
> tarball is served/tracked under the global default.

Read the project's SBOM (may take a few seconds for the async flush):

```sh
curl -fsS http://localhost:8080/admin/projects/acme/dependencies \
  -H "Authorization: Bearer $TOKEN"
```

List, update, and delete projects:

```sh
curl -fsS http://localhost:8080/admin/projects -H "Authorization: Bearer $TOKEN"        # list
curl -fsS -X PUT http://localhost:8080/admin/projects/acme \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"registries":{"npm":{"validation":[{"type":"cve-check","params":{"mode":"deny"}}]}}}'   # update
curl -fsS -X DELETE http://localhost:8080/admin/projects/acme -H "Authorization: Bearer $TOKEN" # delete
```

After a `PUT` or `DELETE` the resolver cache for that key is invalidated, so the
next `/npm/p/acme/…` request rebuilds from the updated config (after `DELETE` it
falls back to the global default).

## 6. A gate in action (403)

With `cve-check` in `mode: deny` against a package that has a known OSV advisory,
the install is rejected — the proxy never serves bytes it has not validated:

```sh
npm install --registry http://localhost:8080/npm <vulnerable-pkg>
# 403: validation "cve-check": <pkg>@<version> has known vulnerabilities: CVE-…
```

Set `cve-check` to `mode: warn` (globally or per-project) to serve + log instead.
`cve-check-retrieval` re-checks OSV on *every* serve, so a CVE published after a
package was first validated blocks the next install even for an already-stored
package.

## More

- The full middleware reference is in [Configuration](configuration).
- The complete feature walkthrough is in the
  [repository README](https://github.com/psenna/dependaproxy#readme).
