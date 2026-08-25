package adapter

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/cveosv"
	"gopkg.in/yaml.v3"
)

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

type fakeAdapter struct{ prefix string }

func (f fakeAdapter) Prefix() string { return f.prefix }
func (f fakeAdapter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}
func (f fakeAdapter) InvalidateProjectCache(string) {}

// TestCVESharedParams covers the shared-OSV-client param scan: validation
// cve-check params win, retrieval cve-check-retrieval is the fallback, neither
// configured yields zero Params, and a malformed params node falls back to zero
// Params without panicking.
func TestCVESharedParams(t *testing.T) {
	// Validation cve-check params win over retrieval cve-check-retrieval.
	cfg := config.RegistryConfig{
		Validation: []config.Middleware{
			{Type: "deny-list-check"},
			{Type: "cve-check", Params: yamlNode("endpoint: http://val.example")},
		},
		Retrieval: []config.Middleware{
			{Type: "cve-check-retrieval", Params: yamlNode("endpoint: http://ret.example")},
		},
	}
	if pr := CVESharedParams(cfg); pr.Endpoint != "http://val.example" {
		t.Fatalf("validation cve-check should win, got endpoint %q", pr.Endpoint)
	}

	// Fallback to retrieval cve-check-retrieval when validation has no cve-check.
	cfg = config.RegistryConfig{
		Validation: []config.Middleware{{Type: "deny-list-check"}},
		Retrieval:  []config.Middleware{{Type: "cve-check-retrieval", Params: yamlNode("endpoint: http://ret.example")}},
	}
	if pr := CVESharedParams(cfg); pr.Endpoint != "http://ret.example" {
		t.Fatalf("retrieval cve-check-retrieval should be the fallback, got endpoint %q", pr.Endpoint)
	}

	// Zero Params when neither is configured.
	if pr := CVESharedParams(config.RegistryConfig{}); pr != (cveosv.Params{}) {
		t.Fatalf("no cve middleware should yield zero Params, got %+v", pr)
	}

	// Malformed params node falls back to zero Params without panicking.
	var bad yaml.Node
	if err := bad.Encode("not-a-mapping"); err != nil {
		t.Fatal(err)
	}
	cfg = config.RegistryConfig{
		Validation: []config.Middleware{{Type: "cve-check", Params: bad}},
	}
	if pr := CVESharedParams(cfg); pr != (cveosv.Params{}) {
		t.Fatalf("malformed params should fall back to zero Params, got %+v", pr)
	}

	// min_severity is carried through from the winning params.
	cfg = config.RegistryConfig{
		Validation: []config.Middleware{
			{Type: "cve-check", Params: yamlNode("endpoint: http://val.example\nmin_severity: high")},
		},
	}
	if pr := CVESharedParams(cfg); pr.MinSeverity != "high" {
		t.Fatalf("validation cve-check min_severity should be carried, got %q", pr.MinSeverity)
	}
	cfg = config.RegistryConfig{
		Retrieval: []config.Middleware{
			{Type: "cve-check-retrieval", Params: yamlNode("endpoint: http://ret.example\nmin_severity: medium")},
		},
	}
	if pr := CVESharedParams(cfg); pr.MinSeverity != "medium" {
		t.Fatalf("retrieval cve-check-retrieval min_severity should be carried, got %q", pr.MinSeverity)
	}

	// cache_enabled/cache_duration are ALWAYS sourced from the retrieval
	// cve-check-retrieval block, even when validation cve-check wins the shared
	// client fields.
	cfg = config.RegistryConfig{
		Validation: []config.Middleware{
			{Type: "cve-check", Params: yamlNode("endpoint: http://val.example")},
		},
		Retrieval: []config.Middleware{
			{Type: "cve-check-retrieval", Params: yamlNode("endpoint: http://ret.example\ncache_enabled: true\ncache_duration: 24h")},
		},
	}
	pr := CVESharedParams(cfg)
	if pr.Endpoint != "http://val.example" {
		t.Fatalf("validation cve-check should win the shared client endpoint, got %q", pr.Endpoint)
	}
	if !pr.CacheEnabled {
		t.Fatal("cache_enabled should be sourced from the retrieval cve-check-retrieval block")
	}
	if pr.CacheDuration != 24*time.Hour {
		t.Fatalf("cache_duration should be sourced from the retrieval cve-check-retrieval block, got %v", pr.CacheDuration)
	}

	// With only a validation cve-check (no retrieval cve-check-retrieval), the
	// cache fields stay at their zero values.
	cfg = config.RegistryConfig{
		Validation: []config.Middleware{
			{Type: "cve-check", Params: yamlNode("endpoint: http://val.example")},
		},
	}
	pr = CVESharedParams(cfg)
	if pr.CacheEnabled {
		t.Fatal("cache_enabled should default false when no retrieval cve-check-retrieval is configured")
	}
	if pr.CacheDuration != 0 {
		t.Fatalf("cache_duration should default zero when no retrieval cve-check-retrieval is configured, got %v", pr.CacheDuration)
	}

	// A retrieval-only config sources both the shared fields and the cache
	// fields from the same block.
	cfg = config.RegistryConfig{
		Retrieval: []config.Middleware{
			{Type: "cve-check-retrieval", Params: yamlNode("endpoint: http://ret.example\ncache_enabled: true\ncache_duration: 48h")},
		},
	}
	pr = CVESharedParams(cfg)
	if pr.Endpoint != "http://ret.example" {
		t.Fatalf("retrieval-only endpoint should be carried, got %q", pr.Endpoint)
	}
	if !pr.CacheEnabled || pr.CacheDuration != 48*time.Hour {
		t.Fatalf("retrieval-only cache fields should be carried, got %+v", pr)
	}
}

// TestFirstMiddlewareParams covers the pre-scan helper adapters use to pin
// dangerous middleware fields (H4): a matching entry decodes into out, a
// present-but-empty-params entry leaves out at its zero value, no match
// leaves out untouched, and a malformed params node doesn't panic (best
// effort -- the real factory surfaces the decode error later).
func TestFirstMiddlewareParams(t *testing.T) {
	type guarddogLike struct {
		Binary  string `yaml:"binary"`
		Sandbox *bool  `yaml:"sandbox"`
	}

	t.Run("matching entry decodes", func(t *testing.T) {
		ms := []config.Middleware{
			{Type: "min-publication-age", Params: yamlNode("min_days: 7")},
			{Type: "guarddog-scan", Params: yamlNode("binary: /usr/bin/guarddog\nsandbox: false")},
		}
		var pr guarddogLike
		FirstMiddlewareParams(ms, "guarddog-scan", &pr)
		if pr.Binary != "/usr/bin/guarddog" || pr.Sandbox == nil || *pr.Sandbox {
			t.Fatalf("got %+v", pr)
		}
	})

	t.Run("no match leaves zero value", func(t *testing.T) {
		ms := []config.Middleware{{Type: "min-publication-age", Params: yamlNode("min_days: 7")}}
		pr := guarddogLike{Binary: "should-not-change"}
		FirstMiddlewareParams(ms, "guarddog-scan", &pr)
		if pr.Binary != "should-not-change" {
			t.Fatalf("no-match call must not touch out, got %+v", pr)
		}
	})

	t.Run("matching entry with no params leaves zero value", func(t *testing.T) {
		ms := []config.Middleware{{Type: "guarddog-scan"}} // Params is the zero yaml.Node
		var pr guarddogLike
		FirstMiddlewareParams(ms, "guarddog-scan", &pr)
		if pr.Binary != "" || pr.Sandbox != nil {
			t.Fatalf("got %+v, want zero value", pr)
		}
	})

	t.Run("malformed params does not panic", func(t *testing.T) {
		ms := []config.Middleware{{Type: "guarddog-scan", Params: yamlNode("binary: [not, a, string]")}}
		var pr guarddogLike
		FirstMiddlewareParams(ms, "guarddog-scan", &pr) // must not panic
	})
}

func TestBuildUnknownType(t *testing.T) {
	Register("unknown-test-type", func(_ context.Context, _ config.RegistryConfig, _ Deps) (Adapter, error) {
		return fakeAdapter{prefix: "/u"}, nil
	})
	_, err := Build(context.Background(), []config.RegistryConfig{{Type: "does-not-exist", Prefix: "/x", Upstream: "u"}}, Deps{})
	if err == nil {
		t.Fatal("want error for unknown registry type")
	}
}

func TestBuildDispatches(t *testing.T) {
	Register("fake-dispatch", func(_ context.Context, _ config.RegistryConfig, _ Deps) (Adapter, error) {
		return fakeAdapter{prefix: "/fake"}, nil
	})
	ads, err := Build(context.Background(), []config.RegistryConfig{{Type: "fake-dispatch", Prefix: "/fake", Upstream: "u"}}, Deps{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(ads) != 1 || ads[0].Prefix() != "/fake" {
		t.Fatalf("got %+v", ads)
	}
}

// TestBuildPropagatesContext proves Build hands its ctx to the factories, so
// startup work (OpenStorage, OpenStore) runs under the server's startup
// context rather than a fresh context.Background.
func TestBuildPropagatesContext(t *testing.T) {
	Register("ctx-propagation-test", func(ctx context.Context, _ config.RegistryConfig, _ Deps) (Adapter, error) {
		if err := ctx.Err(); err != context.Canceled {
			return nil, fmt.Errorf("factory received ctx.Err=%v, want context.Canceled", err)
		}
		return fakeAdapter{prefix: "/c"}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ads, err := Build(ctx, []config.RegistryConfig{{Type: "ctx-propagation-test", Prefix: "/c", Upstream: "u"}}, Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(ads) != 1 || ads[0].Prefix() != "/c" {
		t.Fatalf("got %+v", ads)
	}
}
