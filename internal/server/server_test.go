package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
)

type fakeAd struct{ prefix string }

func (f fakeAd) Prefix() string { return f.prefix }
func (f fakeAd) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}
func (f fakeAd) InvalidateProjectCache(string) {}

func newDispatchServer(t *testing.T, token string) *Server {
	t.Helper()
	adapter.Register("server-dispatch-test", func(cfg config.RegistryConfig, _ adapter.Deps) (adapter.Adapter, error) {
		return fakeAd{prefix: cfg.Prefix}, nil
	})
	cfg := &config.Config{
		Auth:       config.Auth{Token: token},
		Log:        config.Log{Level: "info", Format: "json"},
		Registries: []config.RegistryConfig{{Type: "server-dispatch-test", Prefix: "/t", Upstream: "u"}},
	}
	srv, err := New(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func do(handler http.Handler, target, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestServerHealthzOpen(t *testing.T) {
	h := newDispatchServer(t, "tok").Handler()
	rr := do(h, "/healthz", "")
	if rr.Code != 200 {
		t.Fatalf("healthz code=%d want 200", rr.Code)
	}
}

func TestServerAuthProtectsRegistry(t *testing.T) {
	h := newDispatchServer(t, "tok").Handler()
	if rr := do(h, "/t/foo", ""); rr.Code != 401 {
		t.Errorf("no auth: code=%d want 401", rr.Code)
	}
	if rr := do(h, "/t/foo", "Bearer tok"); rr.Code != 204 {
		t.Errorf("with auth: code=%d want 204 (adapter)", rr.Code)
	}
}

func TestServerAuthDisabledWhenEmpty(t *testing.T) {
	h := newDispatchServer(t, "").Handler()
	if rr := do(h, "/t/foo", ""); rr.Code != 204 {
		t.Errorf("auth disabled: code=%d want 204", rr.Code)
	}
}
