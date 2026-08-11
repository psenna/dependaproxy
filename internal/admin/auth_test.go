package admin_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/admin"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/server"
)

// memStore is a minimal in-memory project.Store for the auth test (external
// package: importing server here would otherwise cycle admin -> server).
type memStore struct {
	cfgs map[string]project.ProjectConfig
}

func (m *memStore) Get(_ context.Context, key string) (project.ProjectConfig, error) {
	if c, ok := m.cfgs[key]; ok {
		return c, nil
	}
	return project.ProjectConfig{}, project.ErrProjectNotFound
}
func (m *memStore) Put(context.Context, project.ProjectConfig) error      { return nil }
func (m *memStore) List(context.Context) ([]project.ProjectConfig, error) { return nil, nil }
func (m *memStore) Delete(context.Context, string) error                  { return nil }

type noopInvalidator struct{}

func (noopInvalidator) Invalidate(string) {}

// TestAdminRequiresAdminToken verifies that mounting the admin handler under
// the server's AdminTokenAuth (as the server does at /admin) gates it with the
// dedicated admin token, NOT the package token.
func TestAdminRequiresAdminToken(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ah := admin.New(&memStore{cfgs: map[string]project.ProjectConfig{}}, nil, noopInvalidator{}, logger, []string{"npm"})
	authd := server.AdminTokenAuth("admintok", logger, ah.Handler())

	// No bearer token -> 401.
	rr := httptest.NewRecorder()
	authd.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/projects", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: code=%d want 401", rr.Code)
	}

	// Correct admin bearer token -> passes through to the handler (200, empty list).
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/projects", nil)
	req.Header.Set("Authorization", "Bearer admintok")
	authd.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("with auth: code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}

	// The package token is NOT valid for the admin gate -> 401.
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/projects", nil)
	req.Header.Set("Authorization", "Bearer tok")
	authd.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("package token: code=%d want 401", rr.Code)
	}
}
