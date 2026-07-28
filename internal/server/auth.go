// Package server wires DependaProxy's HTTP layer. This file provides the
// static bearer-token auth middleware; the routes/handler are added in a later
// task.
package server

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
)

const bearerPrefix = "Bearer "

// TokenAuth wraps next with static bearer-token authentication. If token is
// empty, auth is disabled and next is returned unchanged. exempt, if non-nil,
// returns true for request paths that skip auth (e.g. "/healthz"). A missing or
// mismatched Authorization header yields 401; the configured token is never
// logged.
func TokenAuth(token string, exempt func(string) bool, log *slog.Logger, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exempt != nil && exempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		provided := r.Header.Get("Authorization")
		if !strings.HasPrefix(provided, bearerPrefix) {
			unauthorized(w, log, r, "missing or non-bearer Authorization header")
			return
		}
		cred := provided[len(bearerPrefix):]
		if subtle.ConstantTimeCompare([]byte(cred), []byte(token)) != 1 {
			unauthorized(w, log, r, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter, log *slog.Logger, r *http.Request, reason string) {
	if log != nil {
		log.Warn("auth rejected",
			"path", r.URL.Path,
			"reason", reason,
		)
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="dependaproxy"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
