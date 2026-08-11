package adapter

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
)

type fakeAdapter struct{ prefix string }

func (f fakeAdapter) Prefix() string { return f.prefix }
func (f fakeAdapter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}
func (f fakeAdapter) InvalidateProjectCache(string) {}

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
