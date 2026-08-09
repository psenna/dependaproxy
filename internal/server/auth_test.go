package server

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAuthHandler(token string, exempt func(string) bool, log *slog.Logger) http.Handler {
	return TokenAuth(token, exempt, log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
}

func doReq(h http.Handler, path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestTokenAuthValidBearer(t *testing.T) {
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", "Bearer s3cret-token")
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTokenAuthMissingHeader(t *testing.T) {
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", "")
	if rr.Code != 401 {
		t.Fatalf("code=%d want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate=%q", got)
	}
}

func TestTokenAuthNonBearer(t *testing.T) {
	// A scheme that is neither Bearer nor Basic is rejected.
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", "Digest realm=foo")
	if rr.Code != 401 {
		t.Fatalf("code=%d want 401", rr.Code)
	}
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestTokenAuthValidBasic(t *testing.T) {
	// Basic auth with the token as the password is accepted (pip / Go module
	// proxy clients only speak Basic).
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", basicAuth("dependaproxy", "s3cret-token"))
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("code=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTokenAuthWrongBasicPassword(t *testing.T) {
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", basicAuth("dependaproxy", "wrong"))
	if rr.Code != 401 {
		t.Fatalf("code=%d want 401", rr.Code)
	}
}

func TestTokenAuthMalformedBasic(t *testing.T) {
	h := newAuthHandler("s3cret-token", nil, nil)
	// "Basic " with a non-base64 payload.
	rr := doReq(h, "/express", "Basic not-base64!!!")
	if rr.Code != 401 {
		t.Fatalf("code=%d want 401", rr.Code)
	}
}

func TestTokenAuthWrongBearer(t *testing.T) {
	h := newAuthHandler("s3cret-token", nil, nil)
	rr := doReq(h, "/express", "Bearer wrong-token")
	if rr.Code != 401 {
		t.Fatalf("code=%d want 401", rr.Code)
	}
}

func TestTokenAuthExemptPath(t *testing.T) {
	isHealth := func(p string) bool { return p == "/healthz" }
	h := newAuthHandler("s3cret-token", isHealth, nil)
	rr := doReq(h, "/healthz", "")
	if rr.Code != 200 {
		t.Fatalf("exempt /healthz code=%d want 200", rr.Code)
	}
	// Non-exempt path still requires auth.
	rr = doReq(h, "/express", "")
	if rr.Code != 401 {
		t.Fatalf("non-exempt code=%d want 401", rr.Code)
	}
}

func TestTokenAuthDisabledWhenEmpty(t *testing.T) {
	// Empty token => auth disabled, requests pass without a header.
	h := newAuthHandler("", nil, nil)
	rr := doReq(h, "/express", "")
	if rr.Code != 200 {
		t.Fatalf("code=%d want 200 (auth disabled)", rr.Code)
	}
}

// TestTokenAuthDoesNotLogToken verifies the configured token never appears in
// log output (not even on a rejected request).
func TestTokenAuthDoesNotLogToken(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	token := "super-secret-do-not-log"
	h := newAuthHandler(token, nil, log)

	_ = doReq(h, "/express", "Bearer wrong")
	if strings.Contains(buf.String(), token) {
		t.Fatalf("token leaked into logs: %q", buf.String())
	}
}
