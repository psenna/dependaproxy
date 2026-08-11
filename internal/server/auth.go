// Package server wires DependaProxy's HTTP layer. This file provides the
// static token auth middleware; the routes/handler are added in a later task.
package server

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

const (
	bearerPrefix = "Bearer "
	basicPrefix  = "Basic "
)

// TokenAuth wraps next with static token authentication. It accepts either a
// bearer token (`Authorization: Bearer <token>`) or HTTP Basic auth
// (`Authorization: Basic base64(user:pass)`) where the password equals the
// token (the username is ignored — the password is the credential). The Basic
// form exists so clients that only speak Basic (pip, Go's module proxy client)
// can authenticate with the same shared token. If token is empty, auth is
// disabled and next is returned unchanged. exempt, if non-nil, returns true for
// request paths that skip auth (e.g. "/healthz"). A missing or mismatched
// Authorization header yields 401; the configured token is never logged.
func TokenAuth(token string, exempt func(string) bool, log *slog.Logger, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exempt != nil && exempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		cred, reason, ok := extractCred(r)
		if !ok {
			unauthorized(w, log, r, reason)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cred), []byte(token)) != 1 {
			unauthorized(w, log, r, "invalid token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractCred pulls the bearer or basic credential out of the request's
// Authorization header. It returns ok=false (with a reason) when the header is
// missing, malformed, or uses an unsupported scheme. Shared by TokenAuth and
// AdminTokenAuth so both accept the same credential forms.
func extractCred(r *http.Request) (cred, reason string, ok bool) {
	provided := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(provided, bearerPrefix):
		return provided[len(bearerPrefix):], "", true
	case strings.HasPrefix(provided, basicPrefix):
		_, pass, ok := r.BasicAuth()
		if !ok {
			return "", "malformed basic auth", false
		}
		return pass, "", true
	default:
		return "", "missing or unsupported Authorization header", false
	}
}

func unauthorized(w http.ResponseWriter, log *slog.Logger, r *http.Request, reason string) {
	unauthorizedRealm(w, log, r, reason, `Bearer realm="dependaproxy", Basic realm="dependaproxy"`)
}

// unauthorizedRealm writes the 401 with the given WWW-Authenticate realm and
// logs the rejection at warn (path + reason; the credential is never logged).
func unauthorizedRealm(w http.ResponseWriter, log *slog.Logger, r *http.Request, reason, realm string) {
	if log != nil {
		log.Warn("auth rejected",
			"path", r.URL.Path,
			"reason", reason,
		)
	}
	w.Header().Set("WWW-Authenticate", realm)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
