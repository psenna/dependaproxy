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

func TestLoadFull(t *testing.T) {
	c := mustLoad(t, "full.yaml")

	if c.Server.Addr != ":9090" {
		t.Errorf("addr = %q", c.Server.Addr)
	}
	if c.Auth.Token != "change-me" {
		t.Errorf("auth.token = %q", c.Auth.Token)
	}
	if c.Storage.Type != "postgres" || c.Storage.DSN == "" {
		t.Errorf("storage = %+v", c.Storage)
	}
	if c.Registry != "npm" {
		t.Errorf("registry = %q", c.Registry)
	}
	if c.Upstream != "https://registry.npmjs.org" {
		t.Errorf("upstream = %q", c.Upstream)
	}
	if c.Log.Level != "info" || c.Log.Format != "json" {
		t.Errorf("log = %+v", c.Log)
	}
	if len(c.Validation) != 1 || c.Validation[0].Type != "min-publication-age" {
		t.Fatalf("validation = %+v", c.Validation)
	}
	// Params is a raw yaml.Node; each middleware decodes its own struct.
	var p struct {
		MinDays int `yaml:"min_days"`
	}
	if err := c.Validation[0].Params.Decode(&p); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if p.MinDays != 7 {
		t.Errorf("min_days = %d", p.MinDays)
	}
	if len(c.Retrieval) != 2 {
		t.Fatalf("retrieval len = %d", len(c.Retrieval))
	}
	if c.Retrieval[0].Type != "local-disk-cache" || c.Retrieval[1].Type != "upstream-registry" {
		t.Errorf("retrieval order/types = %+v", c.Retrieval)
	}
	if len(c.Mutation) != 0 {
		t.Errorf("mutation len = %d", len(c.Mutation))
	}
}

func TestLoadMissingUpstream(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "missing_upstream.yaml"))
	if err == nil || !strings.Contains(err.Error(), "upstream is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadBadStorage(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "bad_storage.yaml"))
	if err == nil || !strings.Contains(err.Error(), "postgres") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadEmptyType(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "empty_type.yaml"))
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaults(t *testing.T) {
	c := mustLoad(t, "full.yaml")
	c.Server.Addr = ""
	c.Registry = ""
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.Server.Addr != ":8080" {
		t.Errorf("default addr = %q", c.Server.Addr)
	}
	if c.Registry != "npm" {
		t.Errorf("default registry = %q", c.Registry)
	}
}

func TestRegistryNotNpm(t *testing.T) {
	c := mustLoad(t, "full.yaml")
	c.Registry = "pypi"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "registry must be") {
		t.Fatalf("err = %v", err)
	}
}
