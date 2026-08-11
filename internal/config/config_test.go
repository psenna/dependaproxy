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
	if c.Auth.AdminToken != "change-me-admin" {
		t.Errorf("auth.admin_token = %q", c.Auth.AdminToken)
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
	if len(npm.AllowedUpstreamHosts) != 2 ||
		npm.AllowedUpstreamHosts[0] != "cdn.example.com" ||
		npm.AllowedUpstreamHosts[1] != "files.pythonhosted.org" {
		t.Errorf("npm allowed_upstream_hosts = %v, want [cdn.example.com files.pythonhosted.org] (lowercased, trailing dot and port stripped)", npm.AllowedUpstreamHosts)
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
	if npm.DenyList == nil {
		t.Fatal("npm deny_list = nil, want parsed DenyListConfig")
	}
	if npm.DenyList.Enabled == nil || !*npm.DenyList.Enabled {
		t.Errorf("npm deny_list.enabled = %v, want true", npm.DenyList.Enabled)
	}
	if len(npm.DenyList.RecordMiddlewares) != 2 ||
		npm.DenyList.RecordMiddlewares[0] != "guarddog-scan" || npm.DenyList.RecordMiddlewares[1] != "cve-check" {
		t.Errorf("npm deny_list.record_middlewares = %v, want [guarddog-scan cve-check]", npm.DenyList.RecordMiddlewares)
	}
	py := c.Registries[1]
	if py.Type != "pypi" || py.Prefix != "/pypi" {
		t.Errorf("pypi registry = %+v", py)
	}
}

// TestExampleConfigParses loads the repository's config.example.yaml and checks
// the goproxy block parses with the validation + cache-retrieval chains wired.
func TestExampleConfigParses(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("load config.example.yaml: %v", err)
	}
	if len(c.Registries) < 2 {
		t.Fatalf("registries = %d, want >= 2", len(c.Registries))
	}
	var gop *RegistryConfig
	for i := range c.Registries {
		if c.Registries[i].Type == "goproxy" {
			gop = &c.Registries[i]
			break
		}
	}
	if gop == nil {
		t.Fatal("no goproxy registry in config.example.yaml")
	}
	if gop.Prefix != "/goproxy" || gop.Upstream != "https://proxy.golang.org" {
		t.Errorf("goproxy prefix/upstream = %q/%q", gop.Prefix, gop.Upstream)
	}
	if len(gop.Validation) != 3 ||
		gop.Validation[0].Type != "deny-list-check" ||
		gop.Validation[1].Type != "min-publication-age" ||
		gop.Validation[2].Type != "cve-check" {
		t.Errorf("goproxy validation = %+v, want [deny-list-check min-publication-age cve-check]", gop.Validation)
	}
	if len(gop.Retrieval) != 2 || gop.Retrieval[0].Type != "local-disk-cache" || gop.Retrieval[1].Type != "upstream-registry" {
		t.Errorf("goproxy retrieval = %+v", gop.Retrieval)
	}
	if c.Auth.AdminToken == "" {
		t.Error("auth.admin_token must be set in config.example.yaml")
	}
	if c.Auth.Token != "" && c.Auth.AdminToken == c.Auth.Token {
		t.Error("auth.admin_token must differ from auth.token (privilege separation)")
	}
}

func TestDuplicatePrefix(t *testing.T)     { wantErr(t, "dup_prefix.yaml", "duplicate prefix") }
func TestNoRegistries(t *testing.T)        { wantErr(t, "no_registries.yaml", "at least one registry") }
func TestBadStorage(t *testing.T)          { wantErr(t, "bad_storage.yaml", "postgres") }
func TestMissingUpstream(t *testing.T)     { wantErr(t, "missing_upstream.yaml", "upstream is required") }
func TestEmptyMiddlewareType(t *testing.T) { wantErr(t, "empty_type.yaml", "type is required") }
func TestBadAllowedHost(t *testing.T)      { wantErr(t, "bad_allowed_host.yaml", "allowed_upstream_hosts") }

func TestAdminTokenRequired(t *testing.T) {
	wantErr(t, "no_admin_token.yaml", "auth.admin_token is required")
}

func TestAdminTokenEqualsToken(t *testing.T) {
	wantErr(t, "admin_token_equals_token.yaml", "auth.admin_token must differ from auth.token")
}

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
