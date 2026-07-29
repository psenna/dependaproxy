package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func mustLoad(t *testing.T, name string) *Config {
	t.Helper()
	c, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return c
}

func wantErr(t *testing.T, name, sub string) {
	t.Helper()
	_, err := Load(filepath.Join("testdata", name))
	if err == nil || !strings.Contains(err.Error(), sub) {
		t.Fatalf("load %s: err=%v, want error containing %q", name, err, sub)
	}
}

func TestLoadMulti(t *testing.T) {
	c := mustLoad(t, "multi.yaml")
	if c.Server.Addr != ":9090" {
		t.Errorf("addr = %q", c.Server.Addr)
	}
	if c.Auth.Token != "change-me" {
		t.Errorf("auth.token = %q", c.Auth.Token)
	}
	if c.Storage.Type != "postgres" || c.Storage.DSN == "" {
		t.Errorf("storage = %+v", c.Storage)
	}
	if len(c.Registries) != 2 {
		t.Fatalf("registries = %d, want 2", len(c.Registries))
	}
	npm := c.Registries[0]
	if npm.Type != "npm" || npm.Prefix != "/npm" || npm.Upstream != "https://registry.npmjs.org" {
		t.Errorf("npm registry = %+v", npm)
	}
	if len(npm.Validation) != 1 || npm.Validation[0].Type != "min-publication-age" {
		t.Fatalf("npm validation = %+v", npm.Validation)
	}
	var p struct {
		MinDays int `yaml:"min_days"`
	}
	if err := npm.Validation[0].Params.Decode(&p); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if p.MinDays != 7 {
		t.Errorf("npm min_days = %d", p.MinDays)
	}
	if len(npm.Retrieval) != 2 || npm.Retrieval[0].Type != "local-disk-cache" || npm.Retrieval[1].Type != "upstream-registry" {
		t.Errorf("npm retrieval = %+v", npm.Retrieval)
	}
	py := c.Registries[1]
	if py.Type != "pypi" || py.Prefix != "/pypi" {
		t.Errorf("pypi registry = %+v", py)
	}
}

func TestDuplicatePrefix(t *testing.T)     { wantErr(t, "dup_prefix.yaml", "duplicate prefix") }
func TestNoRegistries(t *testing.T)        { wantErr(t, "no_registries.yaml", "at least one registry") }
func TestBadStorage(t *testing.T)          { wantErr(t, "bad_storage.yaml", "postgres") }
func TestMissingUpstream(t *testing.T)     { wantErr(t, "missing_upstream.yaml", "upstream is required") }
func TestEmptyMiddlewareType(t *testing.T) { wantErr(t, "empty_type.yaml", "type is required") }

func TestDefaults(t *testing.T) {
	c := mustLoad(t, "multi.yaml")
	c.Server.Addr = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Server.Addr != ":8080" {
		t.Errorf("default addr = %q", c.Server.Addr)
	}
}
