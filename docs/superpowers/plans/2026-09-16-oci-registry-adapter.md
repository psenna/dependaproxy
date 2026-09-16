# OCI Registry Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `type: oci` DependaProxy registry adapter that pull-through proxies the Docker Registry HTTP API v2 to one or more upstream container registries, gated by a new wildcard path-allowlist validation middleware, with no caching in v1.

**Architecture:** One adapter instance mounted at the fixed prefix `/v2` (the registry-v2 spec fixes this root; no per-upstream prefix is possible). It parses the leading path segment of the requested repository name to select a configured upstream, runs that upstream's validation chain (headlined by the new `path-allowlist` middleware) against the remaining repository path, and on pass fetches the manifest/blob from the real upstream via `go-containerregistry`, verifying digests locally before serving. `github.com/google/go-containerregistry`'s `remote` package handles each upstream's Bearer-auth handshake; everything else (routing, validation, error-envelope shape) is hand-rolled in this repo, following the existing adapter/pipeline conventions.

**Tech Stack:** Go 1.25, `github.com/google/go-containerregistry` (new dependency), existing `internal/pipeline` validation-middleware framework, `net/http` (stdlib `ServeMux`, no router library — matches every existing adapter).

**Spec:** `docs/superpowers/specs/2026-09-16-oci-registry-adapter-design.md`

## Global Constraints

- v1 has **no caching** — every request re-fetches from upstream. (spec: "v1 scope: no caching")
- Multi-registry addressing is **uniform explicit-prefix for every registry**, including Docker Hub — `dependaproxy:8080/<upstream-name>/<repo>:<tag>`. No `registry-mirrors`/transparent-Hub special case. (spec: "Multi-registry routing")
- The path-allowlist middleware is configured **per upstream**, not globally. (spec: "Allowlist scope")
- Upstream fetches go through `go-containerregistry`'s `remote` package; server-side routing and validation stay hand-rolled. (spec: "Implementation")
- A `type: oci` `registries:` entry's `prefix` **must be exactly `/v2`** — reject otherwise at config load.
- A `type: oci` entry ignores the existing flat `Upstream`/`AllowedUpstreamHosts`/`UpstreamAlias`/`DenyList` fields entirely — only the new `Upstreams []OCIUpstreamConfig` is read. `DenyList` set on a `type: oci` entry is a config error (fail loudly, not a silent no-op) — v1 does not wire deny-list recording for `path-allowlist` denials (a static policy check has nothing worth "remembering" the way a CVE/malware finding does).
- No per-project (`/p/<key>/...`) override support for `oci` — the registry-v2 URL space has no room for a project-key segment without colliding with the upstream-selector segment. `InvalidateProjectCache` is a no-op, matching the documented pattern for "adapters without a resolver."
- v1 targets **public upstream registries only** (anonymous auth). No credential passthrough.
- Blob digest verification only recognizes the `sha256` algorithm — a blob addressed by any other algorithm is rejected with a clear error, not silently unverified.

---

## Task 1: Config schema for `type: oci`

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.OCIUpstreamConfig{Name, Upstream, AllowedUpstreamHosts []string, Validation []Middleware}`, `config.RegistryConfig.Upstreams []OCIUpstreamConfig` (new field). Later tasks read `cfg.Upstreams` from the `Factory`'s `config.RegistryConfig` argument.

- [ ] **Step 1: Write the failing config tests**

Add to `internal/config/config_test.go` (mirror the existing `TestValidate` table-driven style already in that file — find the `func TestValidate(t *testing.T)` table and add these cases, plus one new test function for the OCI-specific shape):

```go
func TestValidateOCI(t *testing.T) {
	base := func() *Config {
		return &Config{
			Auth:    Auth{AdminToken: "admin"},
			Storage: Storage{Type: "postgres"},
			Registries: []RegistryConfig{
				{
					Type:   "oci",
					Prefix: "/v2",
					Upstreams: []OCIUpstreamConfig{
						{Name: "docker", Upstream: "https://registry-1.docker.io"},
					},
				},
			},
		}
	}

	t.Run("valid minimal oci config", func(t *testing.T) {
		c := base()
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("wrong prefix rejected", func(t *testing.T) {
		c := base()
		c.Registries[0].Prefix = "/oci"
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), `prefix must be "/v2"`) {
			t.Fatalf("Validate() = %v, want an error mentioning the fixed /v2 prefix", err)
		}
	})

	t.Run("empty upstreams rejected", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams = nil
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "upstreams") {
			t.Fatalf("Validate() = %v, want an error mentioning upstreams", err)
		}
	})

	t.Run("duplicate upstream names rejected", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams = append(c.Registries[0].Upstreams, OCIUpstreamConfig{Name: "docker", Upstream: "https://ghcr.io"})
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate upstream name") {
			t.Fatalf("Validate() = %v, want an error mentioning a duplicate upstream name", err)
		}
	})

	t.Run("upstream name with a slash rejected", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams[0].Name = "docker/hub"
		if err := c.Validate(); err == nil {
			t.Fatal("Validate() = nil, want an error: upstream name must be a single path segment")
		}
	})

	t.Run("empty upstream url rejected", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams[0].Upstream = ""
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "upstream is required") {
			t.Fatalf("Validate() = %v, want an error mentioning upstream is required", err)
		}
	})

	t.Run("deny_list set on oci entry rejected", func(t *testing.T) {
		c := base()
		enabled := true
		c.Registries[0].DenyList = &DenyListConfig{Enabled: &enabled}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "deny_list is not supported") {
			t.Fatalf("Validate() = %v, want an error rejecting deny_list on an oci entry", err)
		}
	})

	t.Run("flat upstream field ignored, not required, for oci", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstream = "" // the flat field is meaningless for oci; must not trip "upstream is required"
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil (flat Upstream is not used by type: oci)", err)
		}
	})

	t.Run("per-upstream validation middleware type is checked", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams[0].Validation = []Middleware{{Type: ""}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "middleware type is required") {
			t.Fatalf("Validate() = %v, want an error about the empty middleware type", err)
		}
	})

	t.Run("per-upstream allowed_upstream_hosts normalized", func(t *testing.T) {
		c := base()
		c.Registries[0].Upstreams[0].AllowedUpstreamHosts = []string{"  Auth.Docker.IO  "}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
		if got := c.Registries[0].Upstreams[0].AllowedUpstreamHosts[0]; got != "auth.docker.io" {
			t.Errorf("AllowedUpstreamHosts[0] = %q, want normalized %q", got, "auth.docker.io")
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/config/... -run TestValidateOCI -v`
Expected: FAIL — `OCIUpstreamConfig`, `RegistryConfig.Upstreams` undefined (compile error).

- [ ] **Step 3: Add the config types and wire validation**

In `internal/config/config.go`, add the new type right after `DenyListConfig`:

```go
// OCIUpstreamConfig is one named upstream container registry a type: oci
// adapter instance routes to. Name is the leading path segment a client
// selects it with (dependaproxy:8080/<name>/<repo>:<tag>) -- it becomes part
// of the repository name the Docker/OCI client itself parses, so it must be
// a single valid path segment (no slashes).
//
// Unlike every other adapter type, an oci upstream has no Retrieval or
// Mutation chain in v1 (no caching yet -- see the design spec) and no
// project-scoped override support (the registry-v2 URL space has no room
// for a project-key segment without colliding with Name).
type OCIUpstreamConfig struct {
	Name                 string       `yaml:"name"`
	Upstream             string       `yaml:"upstream"`
	AllowedUpstreamHosts []string     `yaml:"allowed_upstream_hosts"`
	Validation           []Middleware `yaml:"validation"`
}
```

Add the field to `RegistryConfig` (after `DenyList`):

```go
	// Upstreams is set ONLY for type: oci -- the named upstream registries
	// this single /v2-mounted adapter instance routes between. Every other
	// adapter type has exactly one Upstream (the flat field above) and
	// leaves this nil. See OCIUpstreamConfig.
	Upstreams []OCIUpstreamConfig `yaml:"upstreams"`
```

In `Validate()`, the existing per-registry loop unconditionally requires
`r.Upstream` and validates `r.AllowedUpstreamHosts`/`r.Validation` etc. on
the flat fields. Change it to branch on `r.Type == "oci"`:

```go
	seen := map[string]bool{}
	for i := range c.Registries {
		r := &c.Registries[i]
		if strings.TrimSpace(r.Type) == "" {
			errs = append(errs, fmt.Sprintf("registries[%d]: type is required", i))
		}
		p := strings.TrimRight(r.Prefix, "/")
		if p == "" {
			errs = append(errs, fmt.Sprintf("registries[%d]: prefix is required", i))
		} else if seen[p] {
			errs = append(errs, fmt.Sprintf("registries[%d]: duplicate prefix %q", i, p))
		} else {
			seen[p] = true
		}
		if r.Type == "oci" {
			errs = append(errs, validateOCIRegistry(i, r)...)
			continue
		}
		if strings.TrimSpace(r.Upstream) == "" {
			errs = append(errs, fmt.Sprintf("registries[%d]: upstream is required", i))
		}
		for j, h := range r.AllowedUpstreamHosts {
			norm, err := normalizeAllowedHost(h)
			if err != nil {
				errs = append(errs, fmt.Sprintf("registries[%d].allowed_upstream_hosts[%d]: %v", i, j, err))
				continue
			}
			r.AllowedUpstreamHosts[j] = norm
		}
		errs = append(errs, validateMiddlewares(fmt.Sprintf("registries[%d].validation", i), r.Validation)...)
		errs = append(errs, validateMiddlewares(fmt.Sprintf("registries[%d].retrieval", i), r.Retrieval)...)
		errs = append(errs, validateMiddlewares(fmt.Sprintf("registries[%d].mutation", i), r.Mutation)...)
	}
```

(The prefix-required/duplicate-prefix block stays shared for every type, since it runs before the branch; only the parts below it become oci-specific via the new `validateOCIRegistry` + `continue`.)

Add `validateOCIRegistry` next to `validateMiddlewares`:

```go
// ociUpstreamNameRE matches a single Docker/OCI repository-name path
// segment: lowercase alphanumerics separated by single ., _, or - (the
// subset of the distribution spec's name-component grammar that is safe to
// use as a leading path segment we later strip).
var ociUpstreamNameRE = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// validateOCIRegistry validates the type: oci-specific shape of registries[i]
// (r.Prefix has already been checked as non-empty/unique by the shared code
// above). The flat Upstream/AllowedUpstreamHosts/Validation/Retrieval/
// Mutation/UpstreamAlias fields are meaningless for oci and are NOT checked
// here even if set -- Load simply never reads them for this type.
func validateOCIRegistry(i int, r *RegistryConfig) []string {
	var errs []string
	if strings.TrimRight(r.Prefix, "/") != "/v2" {
		errs = append(errs, fmt.Sprintf("registries[%d]: prefix must be \"/v2\" for type: oci (got %q)", i, r.Prefix))
	}
	if r.DenyList != nil {
		errs = append(errs, fmt.Sprintf("registries[%d]: deny_list is not supported for type: oci in v1", i))
	}
	if len(r.Upstreams) == 0 {
		errs = append(errs, fmt.Sprintf("registries[%d]: at least one entry in upstreams is required for type: oci", i))
		return errs
	}
	seenNames := map[string]bool{}
	for j := range r.Upstreams {
		u := &r.Upstreams[j]
		name := strings.TrimSpace(u.Name)
		if name == "" {
			errs = append(errs, fmt.Sprintf("registries[%d].upstreams[%d]: name is required", i, j))
		} else if !ociUpstreamNameRE.MatchString(name) {
			errs = append(errs, fmt.Sprintf("registries[%d].upstreams[%d]: name %q must be a single lowercase path segment", i, j, name))
		} else if seenNames[name] {
			errs = append(errs, fmt.Sprintf("registries[%d].upstreams[%d]: duplicate upstream name %q", i, j, name))
		} else {
			seenNames[name] = true
		}
		if strings.TrimSpace(u.Upstream) == "" {
			errs = append(errs, fmt.Sprintf("registries[%d].upstreams[%d]: upstream is required", i, j))
		}
		for k, h := range u.AllowedUpstreamHosts {
			norm, err := normalizeAllowedHost(h)
			if err != nil {
				errs = append(errs, fmt.Sprintf("registries[%d].upstreams[%d].allowed_upstream_hosts[%d]: %v", i, j, k, err))
				continue
			}
			u.AllowedUpstreamHosts[k] = norm
		}
		errs = append(errs, validateMiddlewares(fmt.Sprintf("registries[%d].upstreams[%d].validation", i, j), u.Validation)...)
	}
	return errs
}
```

Add `"regexp"` to the file's import block (it is not currently imported in `config.go`).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/config/... -v -run 'TestValidateOCI|TestValidate$'`
Expected: PASS. Also run the full package to make sure the shared-loop refactor didn't break an existing case: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "config: add type: oci registry schema (Upstreams, validation)"
```

---

## Task 2: Add the go-containerregistry dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/google/go-containerregistry@latest`

- [ ] **Step 2: Verify it resolves and the module still builds**

Run: `go build ./...`
Expected: succeeds (the new dependency is unused so far, which `go build` does not flag — `go vet`/`golangci-lint` would flag an actually-unused *import*, but an unused go.mod requirement is fine; Task 4 is what actually imports it).

- [ ] **Step 3: Tidy and commit**

Run: `go mod tidy`

```bash
git add go.mod go.sum
git commit -m "deps: add go-containerregistry for the oci adapter's upstream fetch"
```

---

## Task 3: `path-allowlist` validation middleware

**Files:**
- Create: `internal/middleware/validation/pathallowlist/pathallowlist.go`
- Create: `internal/middleware/validation/pathallowlist/pathallowlist_test.go`

**Interfaces:**
- Consumes: `pipeline.ValidationMiddleware`, `pipeline.ValidationFactory`, `pipeline.PipelineContext` (existing, `internal/pipeline`).
- Produces: `pathallowlist.Factory pipeline.ValidationFactory` (registered by any adapter under the config type string `"path-allowlist"`; the `oci` adapter in Task 6 does this). `pathallowlist.New(patterns []string) (*Middleware, error)`.

- [ ] **Step 1: Write the failing tests**

```go
package pathallowlist

import (
	"context"
	"log/slog"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func testCtx(pkgName string) *pipeline.PipelineContext {
	return pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "oci/docker", pkgName, "latest", "")
}

func TestMiddleware_Validate(t *testing.T) {
	m, err := New([]string{"library/*", "bitnami/*"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cases := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{"top-level match", "library/nginx", false},
		{"second pattern match", "bitnami/redis", false},
		{"no match", "someuser/nginx", true},
		{"pattern requires the segment present", "library", true}, // "library" alone has no "/*" to match
		{"nested path under an allowed prefix", "library/nginx/extra", true},  // path.Match's "*" does not cross "/"
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.Validate(testCtx(tc.pkg))
			if tc.wantErr && err == nil {
				t.Errorf("Validate(%q) = nil, want an error", tc.pkg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.pkg, err)
			}
		})
	}
}

func TestMiddleware_Name(t *testing.T) {
	m, _ := New([]string{"library/*"})
	if got := m.Name(); got != "path-allowlist" {
		t.Errorf("Name() = %q, want %q", got, "path-allowlist")
	}
}

func TestNew_EmptyPatternsRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want an error: an empty allowlist would deny everything, almost certainly not intended")
	}
	if _, err := New([]string{}); err == nil {
		t.Fatal("New([]string{}) = nil error, want an error")
	}
}

func TestNew_MalformedPatternRejected(t *testing.T) {
	if _, err := New([]string{"["}); err == nil {
		t.Fatal(`New([]string{"["}) = nil error, want an error: "[" is not a valid path.Match pattern`)
	}
}

func TestFactory(t *testing.T) {
	params := yaml.Node{}
	if err := params.Encode(struct {
		Patterns []string `yaml:"patterns"`
	}{Patterns: []string{"library/*"}}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(params)
	if err != nil {
		t.Fatalf("Factory() error = %v", err)
	}
	if err := mw.Validate(testCtx("library/nginx")); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
	if err := mw.Validate(testCtx("someuser/nginx")); err == nil {
		t.Error("Validate() = nil, want an error")
	}
}

func TestFactory_EmptyParamsRejected(t *testing.T) {
	if _, err := Factory(yaml.Node{}); err == nil {
		t.Fatal("Factory(zero yaml.Node) = nil error, want an error (no patterns configured)")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/middleware/validation/pathallowlist/... -v`
Expected: FAIL (package does not exist yet).

- [ ] **Step 3: Implement**

```go
// Package pathallowlist implements a validation middleware that denies a
// request whose ctx.PkgName does not match any of a configured set of glob
// patterns. It is registry-agnostic (any adapter can register it), built for
// the oci adapter's per-upstream repository-path allowlisting but not
// specific to it.
package pathallowlist

import (
	"fmt"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
	"path"
)

// Middleware denies ctx.PkgName unless it matches at least one pattern.
type Middleware struct {
	patterns []string
}

// Name returns the config type string.
func (*Middleware) Name() string { return "path-allowlist" }

// Validate matches ctx.PkgName against each configured pattern with Go's
// path.Match (shell-glob "*" semantics, "*" does not cross a "/"). The first
// match allows the request; no match denies it.
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	for _, p := range m.patterns {
		ok, err := path.Match(p, ctx.PkgName)
		if err != nil {
			// Malformed patterns are rejected at New()/Factory() time, not
			// here -- a pattern that got this far is always well-formed, so
			// this branch is unreachable in practice. Fail closed anyway.
			return fmt.Errorf("path-allowlist: pattern %q: %w", p, err)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("path-allowlist: %q does not match any allowed pattern", ctx.PkgName)
}

// New validates every pattern (path.Match rejects a malformed one) and
// constructs a Middleware. An empty patterns list is rejected: it would deny
// every request, which is never the intended configuration -- an operator who
// wants a fully closed registry should not enable it at all.
func New(patterns []string) (*Middleware, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("path-allowlist: patterns must not be empty")
	}
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("path-allowlist: invalid pattern %q: %w", p, err)
		}
	}
	return &Middleware{patterns: patterns}, nil
}

type params struct {
	Patterns []string `yaml:"patterns"`
}

// Factory builds the middleware from its raw params node, registered by an
// adapter under "path-allowlist".
var Factory pipeline.ValidationFactory = func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("path-allowlist: decode params: %w", err)
		}
	}
	return New(pr.Patterns)
}
```

(Import ordering: put `"path"` with the other stdlib imports, not after `gopkg.in/yaml.v3` — `gofmt`/`goimports` will reorder this automatically; write it in any order and let Step 4's `gofmt` pass fix it.)

- [ ] **Step 4: Run to verify pass**

Run: `gofmt -w internal/middleware/validation/pathallowlist/ && go test ./internal/middleware/validation/pathallowlist/... -v`
Expected: PASS, all subtests green.

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/validation/pathallowlist/
git commit -m "middleware: add path-allowlist validation middleware"
```

---

## Task 4: OCI upstream client (go-containerregistry wrapper)

**Files:**
- Create: `internal/registry/oci/client.go`
- Create: `internal/registry/oci/client_test.go`

**Interfaces:**
- Produces: `oci.Client` with `NewClient(upstreamURL string) (*Client, error)`, `(*Client) GetManifest(ctx, repoPath, ref string) (*ManifestResult, error)`, `(*Client) GetBlob(ctx, repoPath, digest string) ([]byte, string, error)`, `oci.ManifestResult{Bytes []byte, MediaType string, Digest string}`. Task 6/7 adapt these behind a small interface for testability without real network calls.

- [ ] **Step 1: Write the failing (build-tag gated, live-network) test**

This is the one place in the plan that talks to the real internet — every
other test in this plan is offline. Gate it behind a build tag so the
default `go test ./...` never depends on network access, matching
`goproxy/e2e_test.go`'s existing pattern in this repo.

```go
//go:build e2e

package oci

import (
	"context"
	"strings"
	"testing"
)

// TestClient_GetManifestAndBlob_LiveDockerHub pulls the well-known, tiny
// "hello-world" public image from Docker Hub to prove the go-containerregistry
// integration actually round-trips against a real registry, not just a mock.
// Run with: go test -tags e2e ./internal/registry/oci/... -run LiveDockerHub -v
func TestClient_GetManifestAndBlob_LiveDockerHub(t *testing.T) {
	c, err := NewClient("https://registry-1.docker.io")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	ctx := context.Background()

	m, err := c.GetManifest(ctx, "library/hello-world", "latest")
	if err != nil {
		t.Fatalf("GetManifest() error = %v", err)
	}
	if len(m.Bytes) == 0 {
		t.Fatal("GetManifest() returned empty Bytes")
	}
	if !strings.HasPrefix(m.Digest, "sha256:") {
		t.Errorf("Digest = %q, want a sha256: digest", m.Digest)
	}
	if m.MediaType == "" {
		t.Error("MediaType is empty")
	}

	// hello-world's manifest embeds a config blob digest and layer digests --
	// rather than parse the manifest JSON here (adds a real dependency on its
	// exact shape), re-fetch the manifest's own digest as if it were a blob:
	// any digest that appears IN a manifest is always separately fetchable as
	// a blob per the registry-v2 spec, so this proves GetBlob works without
	// needing to decode manifest JSON in this test.
	data, mediaType, err := c.GetBlob(ctx, "library/hello-world", m.Digest)
	if err != nil {
		t.Fatalf("GetBlob() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("GetBlob() returned empty data")
	}
	if mediaType == "" {
		t.Error("GetBlob() mediaType is empty")
	}
}

func TestClient_GetManifest_UnknownRepo(t *testing.T) {
	c, err := NewClient("https://registry-1.docker.io")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	_, err = c.GetManifest(context.Background(), "library/this-image-does-not-exist-12345", "latest")
	if err == nil {
		t.Fatal("GetManifest() = nil error, want an error for an unknown repository")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test -tags e2e ./internal/registry/oci/... -v`
Expected: FAIL (package/`NewClient`/`GetManifest`/`GetBlob` undefined).

- [ ] **Step 3: Implement**

```go
// Package oci implements the type: oci DependaProxy registry adapter: a
// pull-through proxy for the Docker Registry HTTP API v2 / OCI Distribution
// spec. See docs/superpowers/specs/2026-09-16-oci-registry-adapter-design.md.
package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Client fetches manifests and blobs from one upstream registry via
// go-containerregistry, which handles that registry's Bearer-auth handshake.
// v1 fetches anonymously only -- no private-registry credentials yet.
type Client struct {
	host string // upstream registry host[:port], no scheme, e.g. "registry-1.docker.io"
}

// NewClient builds a Client for upstreamURL (e.g. "https://registry-1.docker.io").
func NewClient(upstreamURL string) (*Client, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("oci: parse upstream %q: %w", upstreamURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("oci: upstream %q has no host", upstreamURL)
	}
	return &Client{host: u.Host}, nil
}

// ManifestResult is a fetched manifest: its raw bytes (served verbatim to the
// client) and the digest computed HERE from those bytes -- never trusted
// verbatim from an upstream response header, so a compromised or
// misbehaving upstream cannot lie about what it served.
type ManifestResult struct {
	Bytes     []byte
	MediaType string
	Digest    string // "sha256:<hex>"
}

// GetManifest fetches the manifest for repoPath (e.g. "library/nginx") at ref
// (a tag like "latest", or a digest like "sha256:...").
func (c *Client) GetManifest(ctx context.Context, repoPath, ref string) (*ManifestResult, error) {
	refStr := c.host + "/" + repoPath + refSuffix(ref)
	r, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("oci: parse reference %q: %w", refStr, err)
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(desc.Manifest)
	return &ManifestResult{
		Bytes:     desc.Manifest,
		MediaType: string(desc.MediaType),
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

// GetBlob fetches the blob for repoPath at digest ("sha256:<hex>"), verifying
// the downloaded bytes hash to the requested digest before returning them --
// an upstream cannot serve the wrong bytes under a given digest without
// detection. Only the sha256 algorithm is supported; any other algorithm
// prefix is rejected rather than silently served unverified.
func (c *Client) GetBlob(ctx context.Context, repoPath, digest string) ([]byte, string, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, "", fmt.Errorf("oci: unsupported digest algorithm in %q (only sha256 is verified)", digest)
	}
	refStr := c.host + "/" + repoPath + "@" + digest
	d, err := name.NewDigest(refStr)
	if err != nil {
		return nil, "", fmt.Errorf("oci: parse digest reference %q: %w", refStr, err)
	}
	layer, err := remote.Layer(d, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return nil, "", err
	}
	rc, err := layer.Compressed()
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != digest {
		return nil, "", fmt.Errorf("oci: blob digest mismatch: requested %s, got %s", digest, got)
	}
	mt, err := layer.MediaType()
	if err != nil {
		return nil, "", err
	}
	return data, string(mt), nil
}

// refSuffix returns ":<ref>" for a tag or "@<ref>" for a digest. A digest is
// always of the form "<algorithm>:<hex>" and a Docker tag can never contain
// ":", so the presence of ":" unambiguously distinguishes them.
func refSuffix(ref string) string {
	if strings.Contains(ref, ":") {
		return "@" + ref
	}
	return ":" + ref
}
```

- [ ] **Step 4: Run to verify pass**

Run (requires outbound internet access to Docker Hub): `go test -tags e2e ./internal/registry/oci/... -v`
Expected: PASS.

Also run the default (non-`e2e`) build to confirm nothing here breaks the offline suite: `go build ./... && go vet ./...`
Expected: succeeds (the `e2e`-tagged test file is excluded by default).

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/client.go internal/registry/oci/client_test.go
git commit -m "oci: add go-containerregistry-backed upstream client"
```

---

## Task 5: Registry-v2 error envelope

**Files:**
- Create: `internal/registry/oci/errors.go`
- Create: `internal/registry/oci/errors_test.go`

**Interfaces:**
- Produces: `oci.writeError(w http.ResponseWriter, status int, code, message string)`, error code constants `oci.CodeNameUnknown`, `oci.CodeManifestUnknown`, `oci.CodeBlobUnknown`, `oci.CodeDenied`.

- [ ] **Step 1: Write the failing test**

```go
package oci

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, 404, CodeNameUnknown, "repository name not known to registry")

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v (body: %s)", err, rec.Body.String())
	}
	if len(body.Errors) != 1 {
		t.Fatalf("len(errors) = %d, want 1", len(body.Errors))
	}
	if body.Errors[0].Code != "NAME_UNKNOWN" {
		t.Errorf("code = %q, want NAME_UNKNOWN", body.Errors[0].Code)
	}
	if body.Errors[0].Message != "repository name not known to registry" {
		t.Errorf("message = %q, want the given message", body.Errors[0].Message)
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Pin the exact wire values -- these are read by the Docker/OCI client,
	// not just internal identifiers, so a typo here is a real protocol bug.
	cases := map[string]string{
		CodeNameUnknown:     "NAME_UNKNOWN",
		CodeManifestUnknown: "MANIFEST_UNKNOWN",
		CodeBlobUnknown:     "BLOB_UNKNOWN",
		CodeDenied:          "DENIED",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("constant = %q, want %q", got, want)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/registry/oci/... -run 'TestWriteError|TestErrorCodeConstants' -v`
Expected: FAIL (`writeError`, `Code*` undefined).

- [ ] **Step 3: Implement**

```go
package oci

import (
	"encoding/json"
	"net/http"
)

// Registry-v2 / OCI Distribution spec error codes this adapter returns. The
// exact strings are part of the wire protocol the Docker/OCI client parses.
const (
	CodeNameUnknown     = "NAME_UNKNOWN"
	CodeManifestUnknown = "MANIFEST_UNKNOWN"
	CodeBlobUnknown     = "BLOB_UNKNOWN"
	CodeDenied          = "DENIED"
)

type errorEnvelope struct {
	Errors []errorEntry `json:"errors"`
}

type errorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError writes the registry-v2 error envelope
// {"errors":[{"code":...,"message":...}]} with the given HTTP status, so a
// Docker/OCI client can render a real error instead of "unknown error".
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Errors: []errorEntry{{Code: code, Message: message}}})
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./internal/registry/oci/... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/errors.go internal/registry/oci/errors_test.go
git commit -m "oci: add the registry-v2 JSON error envelope"
```

---

## Task 6: Adapter skeleton — ping route, upstream routing, Factory

**Files:**
- Create: `internal/registry/oci/adapter.go`
- Create: `internal/registry/oci/adapter_test.go`

**Interfaces:**
- Consumes: `adapter.Adapter`, `adapter.Factory`, `adapter.Register`, `adapter.Deps` (`internal/adapter`); `config.RegistryConfig`, `config.OCIUpstreamConfig` (Task 1); `pipeline.NewRegistry`, `pipeline.ValidationPipeline`, `pipeline.PipelineContext`, `pipeline.NewPipelineContext` (`internal/pipeline`); `pathallowlist.Factory` (Task 3); `oci.Client`, `oci.ManifestResult` (Task 4); `oci.writeError`, `oci.Code*` (Task 5).
- Produces: `oci.Factory adapter.Factory` (registered as `"oci"`), the unexported `*adapter` type with a `serve(w, r)` method that Task 7/8 extend with the manifest/blob handlers. `upstream{name string, client manifestBlobGetter, validation pipeline.ValidationPipeline}` — the `manifestBlobGetter` interface (defined here) is what makes Task 7/8's handlers testable without real network calls.

- [ ] **Step 1: Write the failing tests**

```go
package oci

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
)

// fakeClient is a manifestBlobGetter test double -- Task 7/8's handler tests
// reuse this too.
type fakeClient struct {
	manifest    *ManifestResult
	manifestErr error
	blobData    []byte
	blobType    string
	blobErr     error
}

func (f *fakeClient) GetManifest(context.Context, string, string) (*ManifestResult, error) {
	return f.manifest, f.manifestErr
}

func (f *fakeClient) GetBlob(context.Context, string, string) ([]byte, string, error) {
	return f.blobData, f.blobType, f.blobErr
}

func testAdapter(t *testing.T) *ociAdapter {
	t.Helper()
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{
		{Name: "docker", Upstream: "https://registry-1.docker.io"},
	})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	// Swap in a fake client so routing tests never touch the network.
	a.upstreams["docker"].client = &fakeClient{manifestErr: errNotFound}
	return a
}

func TestAdapter_Prefix(t *testing.T) {
	a := testAdapter(t)
	if got := a.Prefix(); got != "/v2" {
		t.Errorf("Prefix() = %q, want /v2", got)
	}
}

func TestAdapter_PingRoute(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
		t.Errorf("Docker-Distribution-API-Version = %q, want registry/2.0", got)
	}
	if got := rec.Body.String(); got != "{}" {
		t.Errorf("body = %q, want {}", got)
	}
}

func TestAdapter_PingRoute_DoesNotTouchAnyUpstream(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifestErr: errUnexpectedCall{}}
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (ping must never call an upstream client)", rec.Code)
	}
}

func TestAdapter_UnknownUpstreamName(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/nope/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeNameUnknown)
}

func TestAdapter_InvalidateProjectCache_NoOp(t *testing.T) {
	a := testAdapter(t)
	a.InvalidateProjectCache("anything") // must not panic
}

func TestFactory_RejectsWrongPrefix(t *testing.T) {
	_, err := Factory(context.Background(), config.RegistryConfig{
		Type: "oci", Prefix: "/oci",
		Upstreams: []config.OCIUpstreamConfig{{Name: "docker", Upstream: "https://registry-1.docker.io"}},
	}, adapterDeps())
	if err == nil {
		t.Fatal("Factory() = nil error, want an error: prefix must be /v2")
	}
}

func TestFactory_BuildsPathAllowlist(t *testing.T) {
	a, err := Factory(context.Background(), config.RegistryConfig{
		Type: "oci", Prefix: "/v2",
		Upstreams: []config.OCIUpstreamConfig{{
			Name: "docker", Upstream: "https://registry-1.docker.io",
			Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
		}},
	}, adapterDeps())
	if err != nil {
		t.Fatalf("Factory() error = %v", err)
	}
	if a.Prefix() != "/v2" {
		t.Errorf("Prefix() = %q, want /v2", a.Prefix())
	}
}
```

Add these small helpers to `adapter_test.go` too (used above and by Task 7/8's tests):

```go
import (
	"errors"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/psenna/dependaproxy/internal/adapter"
)

var errNotFound = errors.New("fake: not found")

type errUnexpectedCall struct{}

func (errUnexpectedCall) Error() string { return "fake client was called when it should not have been" }

func adapterDeps() adapter.Deps {
	return adapter.Deps{Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return time.Time{} }}
}

func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var envelope struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("response body is not the error envelope: %v (body: %s)", err, body)
	}
	if len(envelope.Errors) != 1 || envelope.Errors[0].Code != want {
		t.Fatalf("errors = %+v, want exactly one entry with code %q", envelope.Errors, want)
	}
}

func mustParamsNode(t *testing.T, pattern string) (n yaml.Node) {
	t.Helper()
	if err := n.Encode(struct {
		Patterns []string `yaml:"patterns"`
	}{Patterns: []string{pattern}}); err != nil {
		t.Fatal(err)
	}
	return n
}
```

(`yaml` needs `"gopkg.in/yaml.v3"` imported too — add it alongside the others; `gofmt`/gofmt-driven import grouping is fixed in Step 4 below, as in every prior task.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/registry/oci/... -v`
Expected: FAIL (`newAdapter`, `ociAdapter`, `Factory`, `manifestBlobGetter` undefined).

- [ ] **Step 3: Implement**

```go
package oci

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/validation/pathallowlist"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

func init() { adapter.Register("oci", Factory) }

// manifestBlobGetter is the subset of *Client's behavior the adapter depends
// on, so tests can inject a fake instead of talking to a real registry.
type manifestBlobGetter interface {
	GetManifest(ctx context.Context, repoPath, ref string) (*ManifestResult, error)
	GetBlob(ctx context.Context, repoPath, digest string) ([]byte, string, error)
}

// ociUpstream is one configured, ready-to-serve upstream registry.
type ociUpstream struct {
	name       string
	client     manifestBlobGetter
	validation pipeline.ValidationPipeline
}

// ociAdapter is the type: oci Adapter: one instance mounted at the fixed
// prefix /v2, routing between its configured upstreams by the leading path
// segment of the requested repository name. See the design spec for why a
// single fixed prefix is required by the registry-v2 protocol.
type ociAdapter struct {
	prefix    string
	upstreams map[string]*ociUpstream
	log       adapterLogger
}

// adapterLogger is the tiny slice of *slog.Logger this package needs, kept
// as an interface so tests never have to construct a real one just to
// satisfy a field type. (A concrete *slog.Logger already implements it.)
type adapterLogger interface {
	Warn(msg string, args ...any)
}

// Factory builds the oci adapter from its RegistryConfig + shared Deps.
// Config-shape errors (wrong prefix, no upstreams, unknown middleware type)
// were already caught by config.Validate at load time; Factory re-derives
// nothing that Validate did not already guarantee, except building the
// per-upstream go-containerregistry client and validation pipeline.
func Factory(_ context.Context, cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	return newAdapter(cfg.Prefix, cfg.Upstreams)
}

// newAdapter is Factory's logic, split out so tests can build an adapter
// directly (with real go-containerregistry clients) and then swap in a
// fakeClient per upstream without going through the full Factory/Deps path.
func newAdapter(prefix string, upstreamCfgs []config.OCIUpstreamConfig) (*ociAdapter, error) {
	if strings.TrimRight(prefix, "/") != "/v2" {
		return nil, fmt.Errorf("oci: prefix must be \"/v2\" (got %q) -- the registry-v2 protocol fixes this root", prefix)
	}
	a := &ociAdapter{prefix: prefix, upstreams: map[string]*ociUpstream{}}
	for _, uc := range upstreamCfgs {
		client, err := NewClient(uc.Upstream)
		if err != nil {
			return nil, fmt.Errorf("oci upstream %q: %w", uc.Name, err)
		}
		reg := pipeline.NewRegistry()
		reg.RegisterValidation("path-allowlist", pathallowlist.Factory)
		validation, err := reg.BuildValidation(uc.Validation)
		if err != nil {
			return nil, fmt.Errorf("oci upstream %q: %w", uc.Name, err)
		}
		a.upstreams[uc.Name] = &ociUpstream{name: uc.Name, client: client, validation: validation}
	}
	return a, nil
}

// Prefix returns the fixed URL path prefix "/v2".
func (a *ociAdapter) Prefix() string { return a.prefix }

// Handler serves the registry-v2 routes (paths are relative to /v2 -- the
// server strips the prefix before dispatching, so a. e.g. sees "/" for the
// bare ping and "/docker/library/nginx/manifests/latest" for a pull).
func (a *ociAdapter) Handler() http.Handler { return http.HandlerFunc(a.serve) }

// InvalidateProjectCache is a no-op: oci has no per-project override support
// (see the design spec and this plan's Global Constraints), matching the
// documented pattern for "adapters without a resolver."
func (a *ociAdapter) InvalidateProjectCache(string) {}

func (a *ociAdapter) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		return
	}
	upstreamName, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !ok {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	}
	u, ok := a.upstreams[upstreamName]
	if !ok {
		writeError(w, http.StatusNotFound, CodeNameUnknown, fmt.Sprintf("unknown upstream %q", upstreamName))
		return
	}
	a.route(w, r, u, rest)
}

// route dispatches a request already stripped of its upstream-name segment
// (rest is e.g. "library/nginx/manifests/latest"). Implemented in Task 7
// (manifests) and Task 8 (blobs); left as a 404 here so this task's tests
// (which only exercise the ping route and unknown-upstream routing) pass on
// their own.
func (a *ociAdapter) route(w http.ResponseWriter, r *http.Request, u *ociUpstream, rest string) {
	writeError(w, http.StatusNotFound, CodeNameUnknown, "not found")
}
```

- [ ] **Step 4: Run to verify pass**

Run: `gofmt -w internal/registry/oci/ && go test ./internal/registry/oci/... -v`
Expected: PASS. (`TestFactory_BuildsPathAllowlist` and the manifest/blob-route tests from later tasks are not written yet at this point — only this task's tests exist so far.)

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/adapter.go internal/registry/oci/adapter_test.go
git commit -m "oci: adapter skeleton (ping route, upstream routing, Factory)"
```

---

## Task 7: Manifest route

**Files:**
- Modify: `internal/registry/oci/adapter.go` (`route` gains manifest handling)
- Modify: `internal/registry/oci/adapter_test.go`

**Interfaces:**
- Consumes: `ociUpstream.validation.Run(*pipeline.PipelineContext) error` (`pipeline.ValidationPipeline`, already built in Task 6); `manifestBlobGetter.GetManifest` (Task 4/6); `pipeline.NewPipelineContext` (existing).

- [ ] **Step 1: Write the failing tests**

Add to `adapter_test.go`:

```go
func TestAdapter_ManifestRoute_Success(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifest: &ManifestResult{
		Bytes: []byte(`{"schemaVersion":2}`), MediaType: "application/vnd.docker.distribution.manifest.v2+json", Digest: "sha256:deadbeef",
	}}
	req := httptest.NewRequest("GET", "/docker/library/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "sha256:deadbeef" {
		t.Errorf("Docker-Content-Digest = %q, want sha256:deadbeef", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/vnd.docker.distribution.manifest.v2+json" {
		t.Errorf("Content-Type = %q, want the manifest media type", got)
	}
	if rec.Body.String() != `{"schemaVersion":2}` {
		t.Errorf("body = %q, want the manifest bytes verbatim", rec.Body.String())
	}
}

func TestAdapter_ManifestRoute_DeniedByAllowlist(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name: "docker", Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.upstreams["docker"].client = &fakeClient{manifestErr: errUnexpectedCall{}} // must never be called

	req := httptest.NewRequest("GET", "/docker/someuser/nginx/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeDenied)
}

func TestAdapter_ManifestRoute_UpstreamNotFound(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{manifestErr: errNotFound}
	req := httptest.NewRequest("GET", "/docker/library/nope/manifests/latest", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeManifestUnknown)
}

func TestAdapter_ManifestRoute_MalformedName(t *testing.T) {
	a := testAdapter(t)
	req := httptest.NewRequest("GET", "/docker/manifests-with-no-name", nil) // no "/manifests/<ref>" suffix
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
```

Add `"net/http"` to the test file's imports if not already present from Task 6 (it is, via `httptest`'s package — but the bare `http.StatusForbidden` etc. constants need the `net/http` import explicitly; add it).

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/registry/oci/... -run TestAdapter_ManifestRoute -v`
Expected: FAIL — every case currently gets Task 6's placeholder 404/`CodeNameUnknown` "not found" instead of the manifest-specific behavior (the success and allowlist-denied cases fail outright; the not-found case coincidentally 404s but with the wrong code check once run, since `assertErrorCode` will see `CodeNameUnknown` there — confirm the failure is real, not a false pass, by checking the test output names the expected vs actual code).

- [ ] **Step 3: Implement**

Replace `route`'s placeholder body in `adapter.go`:

```go
func (a *ociAdapter) route(w http.ResponseWriter, r *http.Request, u *ociUpstream, rest string) {
	if name, ref, ok := cutSuffix(rest, "/manifests/"); ok {
		a.serveManifest(w, r, u, name, ref)
		return
	}
	if name, digest, ok := cutSuffix(rest, "/blobs/"); ok {
		a.serveBlob(w, r, u, name, digest)
		return
	}
	writeError(w, http.StatusNotFound, CodeNameUnknown, "not found")
}

// cutSuffix splits "<name><sep><ref>" on the LAST occurrence of sep (a
// repository name may itself contain "/", so this cannot use strings.Cut,
// which splits on the first occurrence). ok is false if sep does not appear,
// or if either side would be empty.
func cutSuffix(s, sep string) (name, ref string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i <= 0 {
		return "", "", false
	}
	name, ref = s[:i], s[i+len(sep):]
	if ref == "" {
		return "", "", false
	}
	return name, ref, true
}

func (a *ociAdapter) serveManifest(w http.ResponseWriter, r *http.Request, u *ociUpstream, repoPath, ref string) {
	ctx := pipeline.NewPipelineContext(r.Context(), nil, "oci/"+u.name, repoPath, ref, "")
	if err := u.validation.Run(ctx); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}
	m, err := u.client.GetManifest(r.Context(), repoPath, ref)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeManifestUnknown, err.Error())
		return
	}
	w.Header().Set("Docker-Content-Digest", m.Digest)
	w.Header().Set("Content-Type", m.MediaType)
	_, _ = w.Write(m.Bytes)
}
```

(`serveBlob` is added in Task 8 — for now `cutSuffix(rest, "/blobs/")` is reachable code but nothing in this task's tests exercises it; that is fine, Task 8 adds its own tests for it. Leave the branch in place now rather than adding it in Task 8, since `route`'s dispatch logic for both suffixes belongs together and re-touching this function per task would fragment one cohesive piece of logic — Task 8 only adds `serveBlob` itself.)

- [ ] **Step 4: Run to verify pass**

Run: `gofmt -w internal/registry/oci/ && go test ./internal/registry/oci/... -v`
Expected: PASS for every `TestAdapter_ManifestRoute_*` case. `TestAdapter_ManifestRoute_MalformedName` and any blob-path test will currently hit the `serveBlob` call added by Task 8's signature — since `serveBlob` does not exist yet, this task's code will not compile until Task 8 adds it. **Resolve this by adding a temporary no-op `serveBlob` in this task**, replaced by Task 8's real implementation:

```go
func (a *ociAdapter) serveBlob(w http.ResponseWriter, r *http.Request, u *ociUpstream, repoPath, digest string) {
	writeError(w, http.StatusNotFound, CodeBlobUnknown, "not found")
}
```

Re-run: `go test ./internal/registry/oci/... -v`
Expected: PASS, including `TestAdapter_ManifestRoute_MalformedName` (no `/manifests/` or `/blobs/` suffix present, so `route` falls through to the final `writeError` — matches the test's 404 expectation).

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/adapter.go internal/registry/oci/adapter_test.go
git commit -m "oci: serve the manifest route (GET /v2/<upstream>/<name>/manifests/<ref>)"
```

---

## Task 8: Blob route

**Files:**
- Modify: `internal/registry/oci/adapter.go` (`serveBlob` replaces Task 7's temporary stub)
- Modify: `internal/registry/oci/adapter_test.go`

**Interfaces:**
- Consumes: `manifestBlobGetter.GetBlob` (Task 4/6).

- [ ] **Step 1: Write the failing tests**

Add to `adapter_test.go`:

```go
func TestAdapter_BlobRoute_Success(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{blobData: []byte("blob-bytes"), blobType: "application/octet-stream"}
	req := httptest.NewRequest("GET", "/docker/library/nginx/blobs/sha256:deadbeef", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Docker-Content-Digest"); got != "sha256:deadbeef" {
		t.Errorf("Docker-Content-Digest = %q, want the requested digest", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream", got)
	}
	if rec.Body.String() != "blob-bytes" {
		t.Errorf("body = %q, want blob-bytes", rec.Body.String())
	}
}

func TestAdapter_BlobRoute_DeniedByAllowlist(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name: "docker", Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{Type: "path-allowlist", Params: mustParamsNode(t, "library/*")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.upstreams["docker"].client = &fakeClient{blobErr: errUnexpectedCall{}}

	req := httptest.NewRequest("GET", "/docker/someuser/nginx/blobs/sha256:deadbeef", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeDenied)
}

func TestAdapter_BlobRoute_UpstreamNotFound(t *testing.T) {
	a := testAdapter(t)
	a.upstreams["docker"].client = &fakeClient{blobErr: errNotFound}
	req := httptest.NewRequest("GET", "/docker/library/nginx/blobs/sha256:missing", nil)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec.Body.Bytes(), CodeBlobUnknown)
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/registry/oci/... -run TestAdapter_BlobRoute -v`
Expected: FAIL — `TestAdapter_BlobRoute_Success` and `_DeniedByAllowlist` fail because Task 7's temporary `serveBlob` stub always 404s and never runs validation; `_UpstreamNotFound` happens to pass already (coincidentally, since the stub also 404s) — note this in the run output, it is expected to be the one already-green case.

- [ ] **Step 3: Implement**

Replace Task 7's temporary `serveBlob` stub in `adapter.go`:

```go
func (a *ociAdapter) serveBlob(w http.ResponseWriter, r *http.Request, u *ociUpstream, repoPath, digest string) {
	ctx := pipeline.NewPipelineContext(r.Context(), nil, "oci/"+u.name, repoPath, digest, "")
	if err := u.validation.Run(ctx); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}
	data, mediaType, err := u.client.GetBlob(r.Context(), repoPath, digest)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeBlobUnknown, err.Error())
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", mediaType)
	_, _ = w.Write(data)
}
```

- [ ] **Step 4: Run to verify pass**

Run: `gofmt -w internal/registry/oci/ && go test ./internal/registry/oci/... -v`
Expected: PASS, every test in the package green.

Run the full existing offline suite too, to confirm nothing elsewhere regressed: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS (the `e2e`-tagged live test from Task 4 is excluded by default, as intended).

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/adapter.go internal/registry/oci/adapter_test.go
git commit -m "oci: serve the blob route (GET /v2/<upstream>/<name>/blobs/<digest>)"
```

---

## Task 9: Wire in, document, example config

**Files:**
- Modify: `cmd/dependaproxy/main.go`
- Modify: `config.example.yaml`
- Modify: `docs/configuration.md`

- [ ] **Step 1: Register the adapter package**

In `cmd/dependaproxy/main.go`, add to the existing blank-import block (alphabetical, matching the existing order):

```go
	_ "github.com/psenna/dependaproxy/internal/registry/goproxy" // register the goproxy adapter
	_ "github.com/psenna/dependaproxy/internal/registry/maven"   // register the maven adapter (skeleton)
	_ "github.com/psenna/dependaproxy/internal/registry/npm"     // register the npm adapter
	_ "github.com/psenna/dependaproxy/internal/registry/oci"     // register the oci adapter
	_ "github.com/psenna/dependaproxy/internal/registry/pypi"    // register the pypi adapter
```

- [ ] **Step 2: Add an example to `config.example.yaml`**

Append a new `registries:` entry (find the existing `registries:` list in this file and add after the last entry, matching its indentation and comment style):

```yaml
  # type: oci -- pull-through proxy for `docker pull`/`docker run`. Unlike
  # every other type, ONE oci entry serves MULTIPLE upstream registries
  # (the registry-v2 protocol fixes the request root at /v2, so prefix must
  # be exactly "/v2" and there can be at most one oci entry). A client
  # addresses an image as <this proxy>/<upstream name>/<repo>:<tag>, e.g.
  # dependaproxy:8080/docker/library/nginx:latest or
  # dependaproxy:8080/ghcr/psenna/ai-sandbox-agent:latest.
  #
  # v1 has NO caching (every pull re-fetches from upstream) and targets
  # public upstreams only (anonymous auth). path-allowlist denies a pull
  # whose repository path (the part after the upstream name) does not match
  # any pattern -- "*" does not cross a "/", so "library/*" allows
  # "library/nginx" but not "library/nginx/extra" or "someuser/nginx".
  - type: oci
    prefix: /v2
    upstreams:
      - name: docker
        upstream: https://registry-1.docker.io
        allowed_upstream_hosts:
          - auth.docker.io
          - production.cloudflare.docker.com
        validation:
          - type: path-allowlist
            params:
              patterns: ["library/*"]
      - name: ghcr
        upstream: https://ghcr.io
        allowed_upstream_hosts:
          - pkg-containers.githubusercontent.com
        validation:
          - type: path-allowlist
            params:
              patterns: ["*/*"]  # allow any owner/repo on ghcr.io
```

- [ ] **Step 3: Document it in `docs/configuration.md`**

Find the section documenting each registry `type:` (npm/pypi/goproxy/maven) and add a matching subsection:

```markdown
### `oci` — container registries (`docker pull`)

Pull-through proxy for the Docker Registry HTTP API v2. Unlike every other
type, **one `oci` entry serves multiple upstream registries** — the
registry-v2 protocol fixes the request root at `/v2`, so `prefix` must be
exactly `/v2` and at most one `oci` entry may be configured.

```yaml
- type: oci
  prefix: /v2
  upstreams:
    - name: docker
      upstream: https://registry-1.docker.io
      allowed_upstream_hosts: [auth.docker.io, production.cloudflare.docker.com]
      validation:
        - type: path-allowlist
          params:
            patterns: ["library/*"]
```

A client addresses an image as `<proxy>/<upstream name>/<repo>:<tag>` —
`docker.io/library/nginx:latest` becomes
`dependaproxy:8080/docker/library/nginx:latest`.

- **`path-allowlist`** (validation) denies a pull whose repository path (the
  part after the upstream name) does not match any of `patterns` — glob
  syntax via Go's `path.Match`, where `*` does not cross a `/`. An empty
  `patterns` list is a config error (it would deny everything).
- v1 has **no caching** and targets **public upstreams only** (anonymous
  auth) — no credential passthrough yet.
- `deny_list` is not supported on an `oci` entry.
```

- [ ] **Step 4: Verify the whole module still builds and tests pass**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/dependaproxy/main.go config.example.yaml docs/configuration.md
git commit -m "oci: wire the adapter into main, document it, add an example config"
```

---

## Task 10: Full-stack live e2e test

**Files:**
- Create: `internal/registry/oci/e2e_test.go`

**Interfaces:**
- Consumes: `newAdapter` (Task 6), `httptest.NewServer` (stdlib) — proves the whole `Handler()` (routing + validation + real client) works together against a real upstream, not just the `Client` wrapper in isolation (Task 4's test) or the routing logic against a fake (Tasks 6-8's tests).

- [ ] **Step 1: Write the failing test**

```go
//go:build e2e

package oci

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
)

// TestFullStack_PullHelloWorld_LiveDockerHub drives the adapter exactly the
// way a real Docker client would: GET /v2/ ping, then a manifest pull, then
// a blob pull for a digest named in that manifest's own response headers --
// through the REAL Factory-built adapter (real config validation, real
// path-allowlist middleware, real go-containerregistry client), served over
// a real HTTP server. Run with:
//   go test -tags e2e ./internal/registry/oci/... -run FullStack -v
func TestFullStack_PullHelloWorld_LiveDockerHub(t *testing.T) {
	a, err := newAdapter("/v2", []config.OCIUpstreamConfig{{
		Name:     "docker",
		Upstream: "https://registry-1.docker.io",
		Validation: []config.Middleware{{
			Type: "path-allowlist", Params: mustParamsNode(t, "library/*"),
		}},
	}})
	if err != nil {
		t.Fatalf("newAdapter() error = %v", err)
	}
	srv := httptest.NewServer(http.StripPrefix("/v2", a.Handler()))
	defer srv.Close()
	client := srv.Client()

	// 1. Ping.
	resp, err := client.Get(srv.URL + "/v2/")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("ping status = %d, want 200", resp.StatusCode)
	}

	// 2. Manifest pull through the allowed upstream+path.
	resp, err = client.Get(srv.URL + "/v2/docker/library/hello-world/manifests/latest")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("manifest status = %d, want 200, body=%s", resp.StatusCode, body)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		t.Fatal("manifest response has no Docker-Content-Digest header")
	}

	// 3. Blob pull for that same digest (any manifest digest is also
	// separately fetchable as a blob per the registry-v2 spec).
	resp, err = client.Get(srv.URL + "/v2/docker/library/hello-world/blobs/" + digest)
	if err != nil {
		t.Fatalf("blob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("blob status = %d, want 200, body=%s", resp.StatusCode, body)
	}

	// 4. A path NOT covered by the "library/*" allowlist is denied, proving
	// the allowlist is actually wired into the live path, not just unit-tested
	// against a fake.
	resp, err = client.Get(srv.URL + "/v2/docker/someuser/hello-world/manifests/latest")
	if err != nil {
		t.Fatalf("denied pull: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied pull status = %d, want 403", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test -tags e2e ./internal/registry/oci/... -run FullStack -v`
Expected: FAIL only if Tasks 1-9 are incomplete or broken; if all prior tasks are done, this may already PASS on first run — in that case skip re-verifying failure and proceed (this task is an integration proof more than new production code, so "write it failing first" does not strictly apply the same way — note this explicitly rather than fabricating an artificial failure step).

- [ ] **Step 3: Run to verify pass**

Run (requires outbound internet access to Docker Hub): `go test -tags e2e ./internal/registry/oci/... -v`
Expected: PASS.

- [ ] **Step 4: Run the full suite one more time end-to-end**

Run: `go build ./... && go vet ./... && go test ./... && go test -tags e2e ./internal/registry/oci/...`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/registry/oci/e2e_test.go
git commit -m "oci: add a full-stack live e2e test (ping, manifest, blob, allowlist deny)"
```

---

## Self-Review

**Spec coverage:**
- v1 no caching — Task 4/6/7/8 call the upstream on every request, no cache layer added. ✅.
- Uniform explicit-prefix multi-registry addressing — Task 6's routing (`upstreamName, rest, ok := strings.Cut(...)`), Task 9's example (`docker`/`ghcr` both addressed the same way). ✅.
- Per-upstream allowlist scope — Task 1's `OCIUpstreamConfig.Validation`, Task 6's per-upstream `pipeline.NewRegistry()`/`BuildValidation`. ✅.
- go-containerregistry for upstream fetch, hand-rolled server/validation — Task 4 (client), Task 6-8 (hand-rolled routing/validation). ✅.
- Fixed `/v2` prefix, ping route — Task 1 (`validateOCIRegistry`), Task 6 (`newAdapter`'s prefix check, `serve`'s ping branch). ✅.
- `path-allowlist` middleware, wildcard, registry-agnostic — Task 3. ✅.
- Config shape (`Upstreams[]`, per-upstream `AllowedUpstreamHosts`/`Validation`) — Task 1. ✅.
- Registry-v2 error envelope + codes — Task 5, used throughout Task 6-8. ✅.
- Digest verification computed locally, not trusted from upstream — Task 4's `GetManifest` (`sha256.Sum256(desc.Manifest)`) and `GetBlob` (hash-then-compare). ✅.
- Testing: unit tests for allowlist, upstream routing, ping-never-touches-upstream, live e2e — Tasks 3, 6, 4, 10. ✅.
- Denylist/audit note from the spec's Testing section — **deliberately dropped**, documented in this plan's Global Constraints ("v1 does not wire deny-list recording... fail loudly if `deny_list` is set on an oci entry" — Task 1's `validateOCIRegistry` rejects it instead). This is a considered deviation from the spec discovered during planning (see below), not an oversight.
- Out-of-scope items (caching, private-registry auth, push, image-content scanning, multi-arch filtering) — untouched, matching the spec. ✅.

**Deviation from the spec, called out explicitly:** the spec's Testing section listed "confirm a path-allowlist denial is recorded [in the deny-list]" as a test to write. Implementing this would require wiring `denylist.Factory`/`denylist.Recorder`/`denylist.OpenStore` per upstream (real added complexity: a Postgres-backed store, an `onFailure` hook, `DefaultRecordedMiddlewares` which does not include `path-allowlist` by default). On reflection, a static policy-based allowlist denial is not the kind of finding the deny-list exists to remember (unlike a CVE or malware finding, an allowlist check is already O(1) and needs no caching for speed) — so this plan has the Factory **reject** `deny_list` on an `oci` entry instead of silently no-op'ing it, and does not implement deny-list recording at all. Flag this to the user when reporting the plan/implementation as a deliberate scope trim, not a gap.

**Placeholder scan:** no TBD/TODO; every step has real code. Task 10's Step 2 explicitly notes why it does not fabricate an artificial failing-test step, rather than silently skipping the "No Placeholders" pattern.

**Type consistency:** `ManifestResult{Bytes, MediaType, Digest}` (Task 4) matches its use in Task 7's `serveManifest`. `manifestBlobGetter` (Task 6) matches `*Client`'s actual method signatures (Task 4) and `fakeClient`'s (Task 6). `OCIUpstreamConfig{Name, Upstream, AllowedUpstreamHosts, Validation}` (Task 1) matches every later reference (Task 6's `newAdapter`, Task 9's example). Error code constants (`CodeNameUnknown` etc., Task 5) are used with the same names throughout Tasks 6-8 and asserted in Task 10.
