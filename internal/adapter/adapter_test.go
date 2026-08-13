package adapter

import (
	"context"
	"fmt"
	"net/http"
	"testing"

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
