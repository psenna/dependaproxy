package adapter

import (
	"net/http"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
)

type fakeAdapter struct{ prefix string }

func (f fakeAdapter) Prefix() string { return f.prefix }
func (f fakeAdapter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}

func TestBuildUnknownType(t *testing.T) {
	Register("unknown-test-type", func(_ config.RegistryConfig, _ Deps) (Adapter, error) {
		return fakeAdapter{prefix: "/u"}, nil
	})
	_, err := Build([]config.RegistryConfig{{Type: "does-not-exist", Prefix: "/x", Upstream: "u"}}, Deps{})
	if err == nil {
		t.Fatal("want error for unknown registry type")
	}
}

func TestBuildDispatches(t *testing.T) {
	Register("fake-dispatch", func(_ config.RegistryConfig, _ Deps) (Adapter, error) {
		return fakeAdapter{prefix: "/fake"}, nil
	})
	ads, err := Build([]config.RegistryConfig{{Type: "fake-dispatch", Prefix: "/fake", Upstream: "u"}}, Deps{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(ads) != 1 || ads[0].Prefix() != "/fake" {
		t.Fatalf("got %+v", ads)
	}
}
