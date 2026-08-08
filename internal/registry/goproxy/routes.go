package goproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// goproxyAdapter is the GOPROXY protocol adapter. Metadata routes (@v/list,
// .info, .mod, @latest) proxy the corresponding upstream endpoint verbatim,
// with the escaped module path from the URL unescaped back to the real module
// path. The .zip route serves the module archive through the validated-module
// trust flow: an unknown (module, version) is fetched, validated (empty chain
// in v1 — validation middlewares land in #75), stored as a sha256 trust
// anchor, and served; a known one is verified against the stored hash on every
// retrieval.
type goproxyAdapter struct {
	prefix   string
	storage  Store
	client   RegistryClient
	resolver *project.Resolver
	tracker  project.DependencyTracker // nil on the dispatch-only/default path
	logger   *slog.Logger
	now      func() time.Time
}

// Prefix returns the URL path prefix.
func (a *goproxyAdapter) Prefix() string { return a.prefix }

// Handler serves the GOPROXY routes (paths are relative to the prefix — the
// server strips the prefix before dispatching).
func (a *goproxyAdapter) Handler() http.Handler { return http.HandlerFunc(a.serve) }

// InvalidateProjectCache drops the cached Resolved pipelines for key so the
// next project-scoped request re-reads the project store.
func (a *goproxyAdapter) InvalidateProjectCache(key string) { a.resolver.Invalidate(key) }

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

// handleZip serves a module archive through the trust flow: a record for
// (module, version) already in the store is served from its sha256 trust
// anchor (verifying upstream every time); an unknown one is fetched, validated,
// stored, and served.
func (a *goproxyAdapter) handleZip(w http.ResponseWriter, r *http.Request, escapedModule, version string) {
	module, ok := a.unescape(w, r, escapedModule)
	if !ok {
		return
	}
	ctx := pipeline.NewPipelineContext(r.Context(), a.logger, "goproxy", module, version, "")
	ctx.ProjectKey = pipeline.ProjectKeyFromContext(r.Context())
	rp, err := a.resolver.Resolve(ctx.Ctx, ctx.ProjectKey)
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "resolve project", err)
		return
	}
	if err := rp.Mutation.RunPreFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation prefetch", err)
		return
	}
	rec, err := a.storage.Get(ctx.Ctx, module, version)
	if err == nil {
		a.serveTrusted(w, r, ctx, rp, rec)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	a.serveUntrusted(w, r, ctx, rp, module, version)
}

func (a *goproxyAdapter) serveTrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, rec Record) {
	body, err := a.fetchBytes(ctx, rp)
	if err != nil {
		a.fetchErr(w, r, err)
		return
	}
	body, ok := a.verifyOrEvict(w, r, ctx, rp, rec.ValidationHash, body)
	if !ok {
		return
	}
	if err := rp.Mutation.RunPostFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	if ctx.Tarball != nil && ctx.Tarball.Bytes != nil {
		body = ctx.Tarball.Bytes
	}
	a.trackDownload(ctx, rec.ValidationHash)
	a.writeTarball(w, body)
}

func (a *goproxyAdapter) serveUntrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, module, version string) {
	body, err := a.fetchBytes(ctx, rp)
	if err != nil {
		a.fetchErr(w, r, err)
		return
	}
	if err := rp.Validation.Run(ctx); err != nil {
		a.fail(w, r, http.StatusForbidden, "validation rejected", err)
		return
	}
	h, _, err := hash.Sha256Hex(bytes.NewReader(body))
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "hash", err)
		return
	}
	rec := Record{
		ModulePath:     module,
		Version:        version,
		ValidationHash: h,
		ValidatedAt:    a.now(),
		Metadata:       metadataJSON(ctx.Metadata),
	}
	if err := a.storage.Put(ctx.Ctx, rec); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "store", err)
		return
	}
	if err := rp.Mutation.RunPostFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	if ctx.Tarball != nil && ctx.Tarball.Bytes != nil {
		body = ctx.Tarball.Bytes
	}
	a.trackDownload(ctx, h)
	a.writeTarball(w, body)
}

// trackDownload emits a dependency download record for project-scoped requests.
// The tracker is nil on the dispatch-only path and the ProjectKey=="" short
// circuit returns before any allocation, so default-path traffic has zero
// overhead.
func (a *goproxyAdapter) trackDownload(ctx *pipeline.PipelineContext, sha256 string) {
	if a.tracker == nil || ctx.ProjectKey == "" {
		return
	}
	a.tracker.Track(project.DependencyRecord{
		ProjectKey: ctx.ProjectKey,
		Registry:   ctx.Registry,
		Pkg:        ctx.PkgName,
		Version:    ctx.Version,
		ArtifactID: ctx.ArtifactID,
		SHA256:     sha256,
	})
}

func (a *goproxyAdapter) verifyOrEvict(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, expected string, body []byte) ([]byte, bool) {
	ok, _, err := hash.VerifyHex(expected, bytes.NewReader(body))
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "verify hash", err)
		return nil, false
	}
	if ok {
		return body, true
	}
	if rp.Cache != nil {
		_ = rp.Cache.Evict(ctx)
	}
	ctx.Tarball = nil // force the upstream middleware to re-fetch the archive
	refetched, err := a.fetchBytes(ctx, rp)
	if err != nil {
		a.fetchErr(w, r, err)
		return nil, false
	}
	ok, _, err = hash.VerifyHex(expected, bytes.NewReader(refetched))
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "verify hash", err)
		return nil, false
	}
	if !ok {
		a.fail(w, r, http.StatusBadGateway, "integrity mismatch: served artifact does not match validated hash")
		return nil, false
	}
	ctx.Tarball = &pipeline.Tarball{Bytes: refetched}
	return refetched, true
}

func (a *goproxyAdapter) fetchBytes(ctx *pipeline.PipelineContext, rp *project.Resolved) ([]byte, error) {
	if err := rp.Retrieval.Run(ctx); err != nil {
		return nil, err
	}
	if ctx.Tarball == nil {
		return nil, pipeline.ErrNoResolver
	}
	return ctx.Tarball.Bytes, nil
}

func (a *goproxyAdapter) fetchErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		a.fail(w, r, http.StatusNotFound, "module or version not found upstream")
	case errors.Is(err, pipeline.ErrRejected):
		a.fail(w, r, http.StatusForbidden, "retrieval rejected", err)
	case errors.Is(err, pipeline.ErrNoResolver):
		a.fail(w, r, http.StatusBadGateway, "no retrieval middleware resolved the module", err)
	default:
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
	}
}

func (a *goproxyAdapter) writeTarball(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body) //nolint:gosec // G705: a proxy serves validated bytes by design
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

func metadataJSON(m map[string]any) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}
