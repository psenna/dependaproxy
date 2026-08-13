package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/project"
)

type fakeAd struct{ prefix string }

func (f fakeAd) Prefix() string { return f.prefix }
func (f fakeAd) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
}
func (f fakeAd) InvalidateProjectCache(string) {}

func newDispatchServer(t *testing.T, token string) *Server {
	t.Helper()
	adapter.Register("server-dispatch-test", func(_ context.Context, cfg config.RegistryConfig, _ adapter.Deps) (adapter.Adapter, error) {
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

// fakeProjectStore is a minimal in-memory project.Store for the admin wiring
// test (the server's Handler mounts /admin only when projectStore is non-nil).
type fakeProjectStore struct{}

func (fakeProjectStore) Get(context.Context, string) (project.ProjectConfig, error) {
	return project.ProjectConfig{}, project.ErrProjectNotFound
}
func (fakeProjectStore) Put(context.Context, project.ProjectConfig) error      { return nil }
func (fakeProjectStore) List(context.Context) ([]project.ProjectConfig, error) { return nil, nil }
func (fakeProjectStore) Delete(context.Context, string) error                  { return nil }

// newDispatchServerWithAdmin builds a Server with a non-nil projectStore so the
// /admin API is mounted, bypassing New (which would need a real DB). adapters
// are set directly so the registry routes exist for the two-tier auth checks.
func newDispatchServerWithAdmin(t *testing.T, token, adminToken string) *Server {
	t.Helper()
	cfg := &config.Config{
		Auth:       config.Auth{Token: token, AdminToken: adminToken},
		Log:        config.Log{Level: "info", Format: "json"},
		Registries: []config.RegistryConfig{{Type: "server-dispatch-admin-test", Prefix: "/t", Upstream: "u"}},
	}
	return &Server{
		cfg:          cfg,
		adapters:     []adapter.Adapter{fakeAd{prefix: "/t"}},
		projectStore: fakeProjectStore{},
		logger:       slog.New(slog.DiscardHandler),
	}
}

func TestServerAdminRequiresAdminToken(t *testing.T) {
	h := newDispatchServerWithAdmin(t, "tok", "admintok").Handler()

	// Package token on /admin -> 401 (privilege separation).
	if rr := do(h, "/admin/projects", "Bearer tok"); rr.Code != 401 {
		t.Errorf("package token on /admin: code=%d want 401", rr.Code)
	}
	// No auth on /admin -> 401.
	if rr := do(h, "/admin/projects", ""); rr.Code != 401 {
		t.Errorf("no auth on /admin: code=%d want 401", rr.Code)
	}
	// Admin token on /admin -> passes the auth gate (200 from the admin handler).
	if rr := do(h, "/admin/projects", "Bearer admintok"); rr.Code != 200 {
		t.Errorf("admin token on /admin: code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}

	// Registry routes still accept only the package token.
	if rr := do(h, "/t/foo", ""); rr.Code != 401 {
		t.Errorf("registry no auth: code=%d want 401", rr.Code)
	}
	if rr := do(h, "/t/foo", "Bearer tok"); rr.Code != 204 {
		t.Errorf("registry with package token: code=%d want 204", rr.Code)
	}
	if rr := do(h, "/t/foo", "Bearer admintok"); rr.Code != 401 {
		t.Errorf("registry with admin token: code=%d want 401", rr.Code)
	}
}

// TestServerWebUIMounted verifies the embedded web UI is mounted at "/" and is
// public, while /healthz stays open, /admin stays admin-token-gated, and
// adapter prefixes stay package-token-protected (ServeMux precedence: the
// most specific pattern wins, so "/" only sees non-registry paths).
func TestServerWebUIMounted(t *testing.T) {
	h := newDispatchServerWithAdmin(t, "tok", "admintok").Handler()

	// Public SPA at /.
	rr := do(h, "/", "")
	if rr.Code != 200 {
		t.Errorf("GET /: code=%d want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /: Content-Type=%q want text/html", ct)
	}
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Errorf("GET /: body missing <html: %q", rr.Body.String())
	}

	// /healthz stays open.
	if rr := do(h, "/healthz", ""); rr.Code != 200 || rr.Body.String() != "ok" {
		t.Errorf("GET /healthz: code=%d body=%q want 200 ok", rr.Code, rr.Body.String())
	}

	// /admin requires the admin token (exempt from the package token, gated by
	// AdminTokenAuth).
	if rr := do(h, "/admin/projects", ""); rr.Code != 401 {
		t.Errorf("GET /admin/projects no auth: code=%d want 401", rr.Code)
	}

	// SPA fallback for client-side routes.
	rr = do(h, "/projects/acme/edit", "")
	if rr.Code != 200 {
		t.Errorf("GET /projects/acme/edit: code=%d want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<html") {
		t.Errorf("GET /projects/acme/edit: body missing <html: %q", rr.Body.String())
	}

	// Adapter routes stay package-token-protected.
	if rr := do(h, "/t/foo", ""); rr.Code != 401 {
		t.Errorf("GET /t/foo no auth: code=%d want 401", rr.Code)
	}
}
