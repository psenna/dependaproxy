// Package config loads and validates DependaProxy's YAML configuration.
//
// v2 is multi-registry: the top-level `registries:` list selects which registry
// adapters are enabled (npm, pypi, maven, ...), each with its own prefix,
// upstream, and middleware ordering. Shared server/auth/storage/log apply to
// the whole instance.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the parsed, validated configuration.
type Config struct {
	Server     Server           `yaml:"server"`
	Auth       Auth             `yaml:"auth"`
	Storage    Storage          `yaml:"storage"`
	Log        Log              `yaml:"log"`
	Registries []RegistryConfig `yaml:"registries"`
}

// Server is the HTTP listener config.
type Server struct {
	Addr string `yaml:"addr"`
}

// Auth holds the static bearer tokens. Token is shared across all registries
// (an empty token disables registry auth); AdminToken gates the admin API at
// /admin and is required whenever storage is configured (the admin API is
// enabled then). The two must differ so a client authorized to pull packages
// cannot mutate project configs.
type Auth struct {
	Token      string `yaml:"token"`
	AdminToken string `yaml:"admin_token"`
}

// Storage is the shared persistence backend config. v2 only supports postgres.
type Storage struct {
	Type string `yaml:"type"`
	DSN  string `yaml:"dsn"`
}

// Log is the structured logger config.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// RegistryConfig configures one registry adapter.
type RegistryConfig struct {
	Type     string `yaml:"type"`     // adapter type: npm, pypi, maven, ...
	Prefix   string `yaml:"prefix"`   // URL path prefix, e.g. "/npm"
	Upstream string `yaml:"upstream"` // upstream registry URL
	// AllowedUpstreamHosts are additional hosts (beyond the base upstream host)
	// the upstream client may fetch from, e.g. CDN mirrors. Every upstream
	// fetch is validated against this allowlist to prevent SSRF via
	// upstream-advertised URLs. The pypi adapter always includes
	// files.pythonhosted.org (PyPI file URLs live there).
	AllowedUpstreamHosts []string `yaml:"allowed_upstream_hosts"`
	// UpstreamAlias enables the pypi path-mirroring alias route
	// (GET <prefix>/upstream/{host}/{path...}), which serves an artifact
	// addressed by its canonical upstream URL path so a lockfile with absolute
	// artifact URLs (uv.lock, pdm.lock) converts to proxy URLs — and back —
	// with one reversible substitution. The host must be in this registry's
	// upstream allowlist; the path prefix is routing decoration and is never
	// fetched. pypi only. Defaults to true; *bool distinguishes unset from an
	// explicit false.
	UpstreamAlias *bool           `yaml:"upstream_alias"`
	Validation    []Middleware    `yaml:"validation"`
	Retrieval     []Middleware    `yaml:"retrieval"`
	Mutation      []Middleware    `yaml:"mutation"`
	DenyList      *DenyListConfig `yaml:"deny_list"`
	// Upstreams is set ONLY for type: oci -- the named upstream registries
	// this single /v2-mounted adapter instance routes between. Every other
	// adapter type has exactly one Upstream (the flat field above) and
	// leaves this nil. See OCIUpstreamConfig.
	Upstreams []OCIUpstreamConfig `yaml:"upstreams"`
}

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

// DenyListConfig configures the deny-list recorder for one registry.
// A nil *DenyListConfig means defaults (recording enabled, default allowlist).
type DenyListConfig struct {
	// Enabled defaults to true when the block is present. *bool distinguishes
	// unset (nil = enabled) from an explicit false.
	Enabled *bool `yaml:"enabled"`
	// RecordMiddlewares defaults to [guarddog-scan, malware-scan, cve-check]
	// when empty.
	RecordMiddlewares []string `yaml:"record_middlewares"`
}

// Middleware is one entry in an ordered pipeline. Params is kept as a raw
// yaml.Node so each middleware's factory decodes its own typed parameters.
type Middleware struct {
	Type   string    `yaml:"type"`
	Params yaml.Node `yaml:"params"`
}

// RegistryMiddlewareConfig is the per-registry middleware portion of a project
// config (no Type/Prefix/Upstream — those are fixed by the adapter). Mirrors the
// middleware lists in RegistryConfig so the same factory decode path
// (config.Middleware.Params yaml.Node) is reused unchanged.
type RegistryMiddlewareConfig struct {
	Validation []Middleware `yaml:"validation"`
	Retrieval  []Middleware `yaml:"retrieval"`
	Mutation   []Middleware `yaml:"mutation"`
}

// Load reads, parses and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: config path is trusted operator input
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate enforces the structural invariants. Known registry types are
// checked by the adapter registry (internal/adapter), not here, to avoid an
// import cycle (adapter imports config).
func (c *Config) Validate() error {
	var errs []string

	if c.Storage.Type != "postgres" {
		errs = append(errs, fmt.Sprintf("storage.type must be %q for v2 (got %q)", "postgres", c.Storage.Type))
	}
	if c.Auth.AdminToken == "" {
		errs = append(errs, "auth.admin_token is required (the admin API at /admin is enabled when storage is configured); set a distinct token to harden admin mutations")
	} else if c.Auth.Token != "" && c.Auth.AdminToken == c.Auth.Token {
		errs = append(errs, "auth.admin_token must differ from auth.token (privilege separation)")
	}
	if len(c.Registries) == 0 {
		errs = append(errs, "at least one registry is required")
	}
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
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}
	return nil
}

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

func validateMiddlewares(name string, ms []Middleware) []string {
	var errs []string
	for i, m := range ms {
		if strings.TrimSpace(m.Type) == "" {
			errs = append(errs, fmt.Sprintf("%s[%d]: middleware type is required", name, i))
		}
	}
	return errs
}

// normalizeAllowedHost lowercases, trims whitespace and a trailing dot, and
// strips a numeric port (hosts are compared on hostname only). Entries that
// carry a scheme, path, query, userinfo, or a non-numeric port are rejected.
func normalizeAllowedHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", errors.New("empty host")
	}
	if strings.ContainsAny(h, "/@?#") {
		return "", fmt.Errorf("malformed host %q", h)
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	if h == "" {
		return "", errors.New("empty host")
	}
	return h, nil
}
