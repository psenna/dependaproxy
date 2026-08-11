package adapter_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/registry/goproxy"
	"github.com/psenna/dependaproxy/internal/storage/db"
	"gopkg.in/yaml.v3"
)

// yamlNode decodes a YAML string into the yaml.Node a config.Middleware.Params
// carries, the same shape the factories receive from config.Load.
func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

// This is an external test package (adapter_test) on purpose: an internal test
// file in package adapter importing the goproxy package — which imports adapter
// — is an import cycle not allowed in test. The external package imports both,
// so the graph stays acyclic while still exercising the real registration.

// goproxyDeps builds the shared Deps for the goproxy Factory. The Factory's
// OpenStorage applies the goproxy schema to the pool itself, so no schema is
// applied here. The goproxy adapter requires the validated-module store, so a
// missing DP_TEST_PG_DSN skips the test.
func goproxyDeps(t *testing.T) adapter.Deps {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping goproxy postgres test")
	}
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return adapter.Deps{
		DB:     d,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    time.Now,
	}
}

func TestGoproxyFactoryBuilds(t *testing.T) {
	a, err := goproxy.Factory(context.Background(), config.RegistryConfig{Type: "goproxy", Prefix: "/goproxy", Upstream: "http://example.com"}, goproxyDeps(t))
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if a.Prefix() != "/goproxy" {
		t.Errorf("prefix = %q", a.Prefix())
	}
}

// TestGoproxyFactoryBuildsWithChains proves the Factory accepts the wired
// validation + cache-retrieval chain shape from config.example.yaml.
func TestGoproxyFactoryBuildsWithChains(t *testing.T) {
	_, err := goproxy.Factory(context.Background(), config.RegistryConfig{
		Type:     "goproxy",
		Prefix:   "/goproxy",
		Upstream: "http://example.com",
		Validation: []config.Middleware{
			{Type: "min-publication-age", Params: yamlNode("min_days: 7")},
			{Type: "cve-check", Params: yamlNode("mode: deny\non_error: fail_open")},
		},
		Retrieval: []config.Middleware{
			{Type: "local-disk-cache", Params: yamlNode("path: " + t.TempDir())},
			{Type: "upstream-registry"},
		},
	}, goproxyDeps(t))
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
}

func TestGoproxyRegistered(t *testing.T) {
	ads, err := adapter.Build(context.Background(), []config.RegistryConfig{{Type: "goproxy", Prefix: "/goproxy", Upstream: "http://example.com"}}, goproxyDeps(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(ads) != 1 || ads[0].Prefix() != "/goproxy" {
		t.Fatalf("got %+v", ads)
	}
}
