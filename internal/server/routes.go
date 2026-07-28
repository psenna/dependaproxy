package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
	"github.com/psenna/dependaproxy/internal/storage"
)

// Handler returns the HTTP handler with auth applied to protected routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/", s.handleRoot)
	exempt := func(p string) bool { return p == "/healthz" }
	return TokenAuth(s.cfg.Auth.Token, exempt, s.logger, mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.fail(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/-/"):
		s.handleTarball(w, r)
	default:
		s.handlePackument(w, r)
	}
}

// handlePackument proxies the upstream packument, rewriting each version's
// dist.tarball to point at the proxy so clients fetch tarballs from here.
func (s *Server) handlePackument(w http.ResponseWriter, r *http.Request) {
	pkg := strings.TrimPrefix(r.URL.Path, "/")
	if pkg == "" {
		s.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	raw, err := s.reg.FetchPackumentRaw(r.Context(), pkg)
	if errors.Is(err, registry.ErrNotFound) {
		s.fail(w, r, http.StatusNotFound, "package not found")
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	rewritten, err := rewriteTarballs(raw, baseURL(r), pkg)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "rewrite packument", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rewritten) //nolint:gosec // G705: a proxy writes upstream content to the response by design
}

// handleTarball serves a package tarball through the trust flow:
//
//	mutation.PreFetch -> storage.Get ->
//	  trusted: retrieval -> verify hash -> (mismatch: evict + refetch + reverify)
//	  untrusted: retrieval -> validation -> hash -> store
//	-> mutation.PostFetch -> serve.
func (s *Server) handleTarball(w http.ResponseWriter, r *http.Request) {
	pkg, version, ok := parseTarballPath(r.URL.Path)
	if !ok {
		s.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	ctx := pipeline.NewPipelineContext(r.Context(), s.logger, s.cfg.Registry, pkg, version)
	if err := s.mutation.RunPreFetch(ctx); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "mutation prefetch", err)
		return
	}

	rec, err := s.storage.Get(ctx.Ctx, pkg, version, s.cfg.Registry)
	if err == nil {
		s.serveTrusted(w, r, ctx, rec)
		return
	}
	if !errors.Is(err, storage.ErrNotFound) {
		s.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	s.serveUntrusted(w, r, ctx, pkg, version)
}

func (s *Server) serveTrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rec storage.PackageRecord) {
	body, err := s.fetchBytes(ctx)
	if err != nil {
		s.fetchErr(w, r, err)
		return
	}
	body, ok := s.verifyOrEvict(w, r, ctx, rec.ValidationHash, body)
	if !ok {
		return
	}
	if err := s.mutation.RunPostFetch(ctx); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	s.writeTarball(w, body)
}

func (s *Server) serveUntrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, pkg, version string) {
	body, err := s.fetchBytes(ctx)
	if err != nil {
		s.fetchErr(w, r, err)
		return
	}
	if err := s.validation.Run(ctx); err != nil {
		s.fail(w, r, http.StatusForbidden, "validation rejected", err)
		return
	}
	h, _, err := hash.Sha256Hex(bytes.NewReader(body))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "hash", err)
		return
	}
	rec := storage.PackageRecord{
		Name:           pkg,
		Version:        version,
		Registry:       s.cfg.Registry,
		ValidationHash: h,
		ValidatedAt:    s.now(),
		Metadata:       metadataJSON(ctx.Metadata),
	}
	if err := s.storage.Put(ctx.Ctx, rec); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "store", err)
		return
	}
	if err := s.mutation.RunPostFetch(ctx); err != nil {
		s.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	s.writeTarball(w, body)
}

// verifyOrEvict checks body's hash against expected. On mismatch it evicts the
// cache, refetches once, and re-verifies. It returns the trusted bytes and
// true, or (nil, false) after writing an error response.
func (s *Server) verifyOrEvict(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, expected string, body []byte) ([]byte, bool) {
	ok, _, err := hash.VerifyHex(expected, bytes.NewReader(body))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "verify hash", err)
		return nil, false
	}
	if ok {
		return body, true
	}
	if s.cache != nil { // corrupted/tampered: evict and refetch once
		_ = s.cache.Evict(ctx)
	}
	// Reset the tarball so the upstream-registry middleware re-fetches it
	// (it skips fetching when ctx.Tarball is already populated).
	ctx.Tarball = nil
	refetched, err := s.fetchBytes(ctx)
	if err != nil {
		s.fetchErr(w, r, err)
		return nil, false
	}
	ok, _, err = hash.VerifyHex(expected, bytes.NewReader(refetched))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "verify hash", err)
		return nil, false
	}
	if !ok {
		s.fail(w, r, http.StatusBadGateway, "integrity mismatch: served artifact does not match validated hash")
		return nil, false
	}
	ctx.Tarball = &pipeline.Tarball{Bytes: refetched}
	return refetched, true
}

// fetchBytes runs the retrieval chain and returns the resolved tarball bytes.
func (s *Server) fetchBytes(ctx *pipeline.PipelineContext) ([]byte, error) {
	if err := s.retrieval.Run(ctx); err != nil {
		return nil, err
	}
	if ctx.Tarball == nil {
		return nil, pipeline.ErrNoResolver
	}
	return ctx.Tarball.Bytes, nil
}

// fetchErr maps a retrieval error to an HTTP status.
func (s *Server) fetchErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, registry.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "package or version not found upstream")
	case errors.Is(err, pipeline.ErrNoResolver):
		s.fail(w, r, http.StatusBadGateway, "no retrieval middleware resolved the package", err)
	default:
		s.fail(w, r, http.StatusBadGateway, "upstream error", err)
	}
}

func (s *Server) writeTarball(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body) //nolint:gosec // G705: a proxy serves validated package bytes by design
}

// fail logs the error (structured) and writes a status response.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, msg string, errs ...error) {
	if len(errs) > 0 && errs[0] != nil {
		s.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg, "err", errs[0].Error())
	} else {
		s.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(msg + "\n"))
}

// baseURL returns the scheme://host the client used to reach the proxy, for
// rewriting dist.tarball URLs.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

// rewriteTarballs rewrites each version's dist.tarball to <base>/<pkg>/-/<version>
// so clients fetch tarballs from the proxy.
func rewriteTarballs(raw []byte, base, pkg string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	vers, ok := doc["versions"].(map[string]any)
	if !ok {
		return json.Marshal(doc)
	}
	for ver, v := range vers {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		dist, _ := vm["dist"].(map[string]any)
		if dist == nil {
			dist = map[string]any{}
			vm["dist"] = dist
		}
		dist["tarball"] = base + "/" + pkg + "/-/" + ver
	}
	return json.Marshal(doc)
}

// parseTarballPath splits "/@scope/pkg/-/1.0.0" into ("@scope/pkg", "1.0.0").
func parseTarballPath(path string) (pkg, version string, ok bool) {
	idx := strings.Index(path, "/-/")
	if idx <= 0 {
		return "", "", false
	}
	pkg = strings.TrimPrefix(path[:idx], "/")
	version = path[idx+3:]
	if pkg == "" || version == "" || strings.Contains(version, "/") {
		return "", "", false
	}
	return pkg, version, true
}

func metadataJSON(m map[string]any) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}
