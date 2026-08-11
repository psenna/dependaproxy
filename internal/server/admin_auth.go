package server

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
)

// AdminTokenAuth wraps next with static token authentication for the admin API
// (/admin). It accepts the same bearer/basic credential forms as TokenAuth
// (see extractCred) but uses a distinct auth realm so clients can tell the two
// gates apart. Unlike TokenAuth, an empty token FAILS CLOSED: the admin API
// must never be left open, so a handler constructed with "" rejects every
// request. The configured token is never logged.
func AdminTokenAuth(token string, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			adminUnauthorized(w, log, r, "admin token not configured")
			return
		}
		cred, reason, ok := extractCred(r)
		if !ok {
			adminUnauthorized(w, log, r, reason)
			return
		}
		if subtle.ConstantTimeCompare([]byte(cred), []byte(token)) != 1 {
			adminUnauthorized(w, log, r, "invalid token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func adminUnauthorized(w http.ResponseWriter, log *slog.Logger, r *http.Request, reason string) {
	unauthorizedRealm(w, log, r, reason, `Bearer realm="dependaproxy-admin"`)
}
