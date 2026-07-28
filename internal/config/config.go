// Package config loads and validates DependaProxy's YAML configuration.
//
// Config is intentionally a pure data + structural-validation layer: it knows
// the shape of the configuration and the v1 invariants (registry must be npm,
// storage must be postgres, required fields, non-empty middleware types) but
// it does NOT know which middleware type names are valid — that belongs to the
// pipeline builder (internal/pipeline), which owns the middleware factory
// registry. This keeps config decoupled from every middleware package.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the parsed, validated configuration.
type Config struct {
	Server     Server       `yaml:"server"`
	Auth       Auth         `yaml:"auth"`
	Storage    Storage      `yaml:"storage"`
	Registry   string       `yaml:"registry"`
	Upstream   string       `yaml:"upstream"`
	Log        Log          `yaml:"log"`
	Validation []Middleware `yaml:"validation"`
	Retrieval  []Middleware `yaml:"retrieval"`
	Mutation   []Middleware `yaml:"mutation"`
}

// Server is the HTTP listener config.
type Server struct {
	Addr string `yaml:"addr"`
}

// Auth holds the optional static bearer token. An empty token disables auth.
type Auth struct {
	Token string `yaml:"token"`
}

// Storage is the persistence backend config. v1 only supports postgres.
type Storage struct {
	Type string `yaml:"type"`
	DSN  string `yaml:"dsn"`
}

// Log is the structured logger config.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Middleware is one entry in an ordered pipeline. Params is kept as a raw
// yaml.Node so each middleware's factory decodes its own typed parameters.
type Middleware struct {
	Type   string    `yaml:"type"`
	Params yaml.Node `yaml:"params"`
}

// Load reads, parses and validates the configuration file at path.
func Load(path string) (*Config, error) {
	// path is an operator-supplied config file path, not untrusted input.
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

// Validate enforces the v1 structural invariants.
func (c *Config) Validate() error {
	var errs []string

	if strings.TrimSpace(c.Upstream) == "" {
		errs = append(errs, "upstream is required")
	}
	if c.Storage.Type != "postgres" {
		errs = append(errs, fmt.Sprintf("storage.type must be %q for v1 (got %q)", "postgres", c.Storage.Type))
	}
	// v1 only supports the npm registry. Default empty -> npm for convenience.
	if c.Registry == "" {
		c.Registry = "npm"
	} else if c.Registry != "npm" {
		errs = append(errs, fmt.Sprintf("registry must be %q for v1 (got %q)", "npm", c.Registry))
	}
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}

	errs = append(errs, validateMiddlewares("validation", c.Validation)...)
	errs = append(errs, validateMiddlewares("retrieval", c.Retrieval)...)
	errs = append(errs, validateMiddlewares("mutation", c.Mutation)...)

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
