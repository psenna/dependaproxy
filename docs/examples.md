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

## 5. Lockfile portability: install a canonical uv.lock through the proxy

Lock-driven installers fetch the absolute URL baked into the lockfile, not the
index you configure — `uv sync --frozen` ignores `UV_DEFAULT_INDEX` for
already-locked packages, and `--locked` aborts on any change. The pypi adapter
serves `GET /pypi/upstream/{host}/{path...}` as a reversible alias for
`/pypi/files/{name}/{version}/{filename}` (same trust flow, same index lookup;
`{host}` must be allowlisted, the path is never fetched), so you can point a
committed `uv.lock` at the proxy with one `sed` and restore it with the inverse:

```sh
cp uv.lock /tmp/uv.lock.bak
sed -i 's#https://files\.pythonhosted\.org/#http://dependaproxy:8080/pypi/upstream/files.pythonhosted.org/#g' uv.lock
UV_DEFAULT_INDEX=http://dependaproxy:8080/pypi/simple uv sync --frozen --all-extras
cp /tmp/uv.lock.bak uv.lock
```

`UV_DEFAULT_INDEX` is still needed, only to resolve `[build-system] requires`
(e.g. hatchling) — build-backend deps are not in `uv.lock`.

Inverse rewrite (restore canonical URLs):

```sh
sed -i 's#http://dependaproxy:8080/pypi/upstream/#https://#g' uv.lock
```

Keep the committed lock canonical and do the rewrite at build time — e.g. a git
clean/smudge filter:

```
# .gitattributes
uv.lock filter=dependaproxy
```

```sh
git config filter.dependaproxy.clean  "sed 's#http://dependaproxy:8080/pypi/upstream/#https://#g'"
git config filter.dependaproxy.smudge "sed 's#https://files\.pythonhosted\.org/#http://dependaproxy:8080/pypi/upstream/files.pythonhosted.org/#g'"
```

No validation is relaxed: a lock pinning a release younger than
`min-publication-age` still `403`s (use `[tool.uv] exclude-newer`). With
`auth.token` set, add a `.netrc` entry for the proxy host rather than baking
`user:token@` into the lock.

**npm:** nothing server-side — `/npm/{pkg}/-/{file}.tgz` already mirrors
`registry.npmjs.org`; `npm config set replace-registry-host=always` rewrites the
`resolved` URLs in `package-lock.json` at install time.

**Go modules** and pip `--require-hashes` / pip-tools `--generate-hashes` need
nothing: `go.sum` is hash-only with `GOPROXY` as the redirect, and a hash-pinned
`requirements.txt` pins `name==version` + hashes and resolves through the
configured index.

## 6. Per-project config + SBOM

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

## 7. A gate in action (403)

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
