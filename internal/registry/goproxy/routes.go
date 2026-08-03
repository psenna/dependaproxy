package goproxy

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

// goproxyAdapter is the GOPROXY protocol adapter. v1 is pass-through only:
// every route proxies the corresponding upstream endpoint verbatim, with the
// escaped module path from the URL unescaped back to the real module path.
type goproxyAdapter struct {
	prefix string
	client RegistryClient
	logger *slog.Logger
	now    func() time.Time
}

// Prefix returns the URL path prefix.
func (a *goproxyAdapter) Prefix() string { return a.prefix }

// Handler serves the GOPROXY routes (paths are relative to the prefix — the
// server strips the prefix before dispatching).
func (a *goproxyAdapter) Handler() http.Handler { return http.HandlerFunc(a.serve) }

// InvalidateProjectCache is a no-op: the goproxy adapter has no resolver yet.
func (a *goproxyAdapter) InvalidateProjectCache(string) {}

func (a *goproxyAdapter) serve(w http.ResponseWriter, r *http.Request) {
	remaining, key := pipeline.ParseProjectPath(r.URL.Path)
	if key != "" {
		r = r.WithContext(pipeline.ContextWithProjectKey(r.Context(), key))
		r.URL.Path = remaining
	}
	if r.Method != http.MethodGet {
		a.fail(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case strings.HasSuffix(path, "/@latest"):
		a.handleLatest(w, r, strings.TrimSuffix(path, "/@latest"))
	default:
		idx := strings.Index(path, "/@v/")
		if idx <= 0 {
			a.fail(w, r, http.StatusNotFound, "not found")
			return
		}
		module := path[:idx]
		rest := path[idx+4:]
		if rest == "list" {
			a.handleList(w, r, module)
			return
		}
		dot := strings.LastIndex(rest, ".")
		if dot < 0 {
			a.fail(w, r, http.StatusNotFound, "not found")
			return
		}
		version, ext := rest[:dot], rest[dot+1:]
		switch ext {
		case "info":
			a.handleInfo(w, r, module, version)
		case "mod":
			a.handleMod(w, r, module, version)
		case "zip":
			a.handleZip(w, r, module, version)
		default:
			a.fail(w, r, http.StatusNotFound, "not found")
		}
	}
}

// unescape validates the escaped module path from the URL and returns the real
// module path. A malformed escaped path is a 400.
func (a *goproxyAdapter) unescape(w http.ResponseWriter, r *http.Request, escaped string) (string, bool) {
	module, err := unescapePath(escaped)
	if err != nil {
		a.fail(w, r, http.StatusBadRequest, "invalid module path", err)
		return "", false
	}
	return module, true
}

func (a *goproxyAdapter) handleList(w http.ResponseWriter, r *http.Request, escapedModule string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	versions, err := a.client.FetchList(r.Context(), module)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "module not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, strings.Join(versions, "\n")+"\n") //nolint:gosec // G705: a proxy writes upstream content by design
}

func (a *goproxyAdapter) handleInfo(w http.ResponseWriter, r *http.Request, escapedModule, version string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	info, err := a.client.FetchInfo(r.Context(), module, version)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "module not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (a *goproxyAdapter) handleMod(w http.ResponseWriter, r *http.Request, escapedModule, version string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	b, err := a.client.FetchMod(r.Context(), module, version)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "module not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b) //nolint:gosec // G705: a proxy writes upstream content by design
}

func (a *goproxyAdapter) handleZip(w http.ResponseWriter, r *http.Request, escapedModule, version string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	rc, n, err := a.client.FetchZip(r.Context(), module, version)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "module not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", "application/zip")
	if n > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	}
	_, _ = io.Copy(w, rc) //nolint:gosec // G705: a proxy streams upstream content by design
}

func (a *goproxyAdapter) handleLatest(w http.ResponseWriter, r *http.Request, escapedModule string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	info, err := a.client.FetchLatest(r.Context(), module)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "module not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (a *goproxyAdapter) fail(w http.ResponseWriter, r *http.Request, code int, msg string, errs ...error) {
	if len(errs) > 0 && errs[0] != nil {
		a.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg, "err", errs[0].Error())
	} else {
		a.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	if len(errs) > 0 && errs[0] != nil {
		// Surface the underlying reason (e.g. the escaped-path error) so clients
		// see why the request failed, not just the short msg.
		msg += ": " + errs[0].Error()
	}
	_, _ = w.Write([]byte(msg + "\n")) //nolint:gosec // G705: plain-text error detail, not HTML
}
