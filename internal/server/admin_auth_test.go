package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestAdminTokenAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	h := AdminTokenAuth("admintok", slog.New(slog.DiscardHandler), next)

	// Missing header -> 401.
	if rr := do(h, "/admin/projects", ""); rr.Code != 401 {
		t.Errorf("missing header: code=%d want 401", rr.Code)
	}

	// Wrong bearer -> 401.
	if rr := do(h, "/admin/projects", "Bearer wrong"); rr.Code != 401 {
		t.Errorf("wrong bearer: code=%d want 401", rr.Code)
	}

	// A token valid for the package TokenAuth is NOT valid here -> 401.
	if rr := do(h, "/admin/projects", "Bearer tok"); rr.Code != 401 {
		t.Errorf("package token: code=%d want 401", rr.Code)
	}

	// Correct admin bearer -> passes through.
	if rr := do(h, "/admin/projects", "Bearer admintok"); rr.Code != 204 {
		t.Errorf("correct bearer: code=%d want 204", rr.Code)
	}
}

func TestAdminTokenAuthRealm(t *testing.T) {
	h := AdminTokenAuth("admintok", slog.New(slog.DiscardHandler), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	rr := do(h, "/admin/projects", "")
	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="dependaproxy-admin"` {
		t.Errorf("WWW-Authenticate = %q, want %q", got, `Bearer realm="dependaproxy-admin"`)
	}
}

func TestAdminTokenAuthEmptyFailsClosed(t *testing.T) {
	h := AdminTokenAuth("", slog.New(slog.DiscardHandler), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	if rr := do(h, "/admin/projects", "Bearer anything"); rr.Code != 401 {
		t.Errorf("empty token: code=%d want 401 (fail closed)", rr.Code)
	}
}

func TestAdminTokenAuthDoesNotLogToken(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	h := AdminTokenAuth("admintok", logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	do(h, "/admin/projects", "Bearer admintok")
	do(h, "/admin/projects", "Bearer wrong")
	out := buf.String()
	if strings.Contains(out, "admintok") {
		t.Errorf("log leaked the admin token: %s", out)
	}
	if !strings.Contains(out, "auth rejected") {
		t.Errorf("expected an auth rejected log, got: %s", out)
	}
}
