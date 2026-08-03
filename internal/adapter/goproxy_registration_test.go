package adapter_test

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/registry/goproxy"
)

// This is an external test package (adapter_test) on purpose: an internal test
// file in package adapter importing the goproxy package — which imports adapter
// — is an import cycle not allowed in test. The external package imports both,
// so the graph stays acyclic while still exercising the real registration.

func goproxyDeps() adapter.Deps {
	return adapter.Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: time.Now}
}

func TestGoproxyFactoryBuilds(t *testing.T) {
	a, err := goproxy.Factory(config.RegistryConfig{Type: "goproxy", Prefix: "/goproxy", Upstream: "http://example.com"}, goproxyDeps())
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if a.Prefix() != "/goproxy" {
		t.Errorf("prefix = %q", a.Prefix())
	}
}

func TestGoproxyRegistered(t *testing.T) {
	ads, err := adapter.Build([]config.RegistryConfig{{Type: "goproxy", Prefix: "/goproxy", Upstream: "http://example.com"}}, goproxyDeps())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(ads) != 1 || ads[0].Prefix() != "/goproxy" {
		t.Fatalf("got %+v", ads)
	}
}
