// Package config loads and validates DependaProxy's YAML configuration.
//
// v2 is multi-registry: the top-level `registries:` list selects which registry
// adapters are enabled (npm, pypi, maven, ...), each with its own prefix,
// upstream, and middleware ordering. Shared server/auth/storage/log apply to
// the whole instance.
package config

import (
	"fmt"
	"os"
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

// Auth holds the optional static bearer token (shared across all registries).
// An empty token disables auth.
type Auth struct {
	Token string `yaml:"token"`
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
	Type       string       `yaml:"type"`     // adapter type: npm, pypi, maven, ...
	Prefix     string       `yaml:"prefix"`   // URL path prefix, e.g. "/npm"
	Upstream   string       `yaml:"upstream"` // upstream registry URL
	Validation []Middleware `yaml:"validation"`
	Retrieval  []Middleware `yaml:"retrieval"`
	Mutation   []Middleware `yaml:"mutation"`
}

// Middleware is one entry in an ordered pipeline. Params is kept as a raw
// yaml.Node so each middleware's factory decodes its own typed parameters.
type Middleware struct {
	Type   string    `yaml:"type"`
	Params yaml.Node `yaml:"params"`
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
	if len(c.Registries) == 0 {
		errs = append(errs, "at least one registry is required")
	}
	seen := map[string]bool{}
	for i, r := range c.Registries {
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
		if strings.TrimSpace(r.Upstream) == "" {
			errs = append(errs, fmt.Sprintf("registries[%d]: upstream is required", i))
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

func validateMiddlewares(name string, ms []Middleware) []string {
	var errs []string
	for i, m := range ms {
		if strings.TrimSpace(m.Type) == "" {
			errs = append(errs, fmt.Sprintf("%s[%d]: middleware type is required", name, i))
		}
	}
	return errs
}
