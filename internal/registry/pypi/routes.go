package pypi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/pypifilename"
)

// unparseableVersion is the version path segment used for files whose filename
// cannot be parsed to a version. The proxy rewrites every file URL to its own
// route (never leaving the upstream URL intact) and 404s these files on the
// proxy side, so clients can never bypass the trust flow by fetching upstream.
const unparseableVersion = "_"

// pypiAdapter is the PyPI registry adapter. Pipelines are resolved per request
// scope (default or project) via the project resolver.
type pypiAdapter struct {
	prefix   string
	storage  Store
	client   RegistryClient
	resolver *project.Resolver
	tracker  project.DependencyTracker // nil on the dispatch-only/default path
	logger   *slog.Logger
	now      func() time.Time
}

// Prefix returns the URL path prefix.
func (a *pypiAdapter) Prefix() string { return a.prefix }

// InvalidateProjectCache drops the cached Resolved pipelines for key so the
// next project-scoped request re-reads the project store.
func (a *pypiAdapter) InvalidateProjectCache(key string) { a.resolver.Invalidate(key) }

// Handler serves the PyPI routes (paths are relative to the prefix — the server
// strips the prefix before dispatching).
func (a *pypiAdapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /simple/{name}/", a.handleIndex)
	mux.HandleFunc("GET /files/{name}/{version}/{filename}", a.handleFile)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if remaining, key := pipeline.ParseProjectPath(r.URL.Path); key != "" {
			r = r.WithContext(pipeline.ContextWithProjectKey(r.Context(), key))
			r.URL.Path = remaining
		}
		mux.ServeHTTP(w, r)
	})
}

// handleIndex proxies the upstream PEP 691 JSON index, rewriting each file's
// url to point at the proxy (under this adapter's prefix).
func (a *pypiAdapter) handleIndex(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	raw, _, err := a.client.FetchIndexRaw(r.Context(), name, acceptJSON)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	rewritten, err := rewriteIndexJSON(raw, a.baseURL(r), name)
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "rewrite index", err)
		return
	}
	w.Header().Set("Content-Type", acceptJSON)
	_, _ = w.Write(rewritten) //nolint:gosec // G705: a proxy writes upstream content by design
}

// handleFile serves a file through the trust flow.
func (a *pypiAdapter) handleFile(w http.ResponseWriter, r *http.Request) {
	pkg := r.PathValue("name")
	version := r.PathValue("version")
	filename := r.PathValue("filename")
	if pkg == "" || version == "" || filename == "" {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	// Security boundary (issue #116): a filename that cannot be parsed to a
	// version is served by no route — the index rewrite maps it to the "_"
	// sentinel version, and this gate 404s it here. Re-parse the filename
	// itself (not the path version sentinel) so the two stay symmetric.
	if v, err := pypifilename.ParseVersion(filename); err != nil || v == "" {
		a.fail(w, r, http.StatusNotFound, "unparseable filename")
		return
	}
	ctx := pipeline.NewPipelineContext(r.Context(), a.logger, "pypi", pkg, version, filename)
	ctx.ProjectKey = pipeline.ProjectKeyFromContext(r.Context())
	rp, err := a.resolver.Resolve(ctx.ProjectKey)
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "resolve project", err)
		return
	}
	if err := rp.Mutation.RunPreFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation prefetch", err)
		return
	}
	rec, err := a.storage.Get(ctx.Ctx, pkg, version, filename)
	if err == nil {
		a.serveTrusted(w, r, ctx, rp, rec)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	a.serveUntrusted(w, r, ctx, rp, pkg, version, filename)
}

func (a *pypiAdapter) serveTrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, rec Record) {
	body, err := a.fetchBytes(ctx, rp)
	if err != nil {
		a.fetchErr(w, r, err)
		return
	}
	body, ok := a.verifyOrEvict(w, r, ctx, rp, rec.Sha256, body)
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
	a.trackDownload(ctx, rec.Sha256)
	a.writeFile(w, body)
}

func (a *pypiAdapter) serveUntrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, pkg, version, filename string) {
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
	info, err := pypifilename.Parse(filename)
	if err != nil {
		// Defense-in-depth: handleFile gates on ParseVersion before this
		// point, so this branch is normally unreachable. 404 (not 500) so an
		// unparseable filename is never served as a valid artifact.
		a.fail(w, r, http.StatusNotFound, "parse filename", err)
		return
	}
	rec := Record{
		Name:        pkg,
		Version:     version,
		Filename:    filename,
		FileType:    info.FileType,
		PythonTag:   info.PythonTag,
		AbiTag:      info.AbiTag,
		PlatformTag: info.PlatformTag,
		Sha256:      h,
		ValidatedAt: a.now(),
		Metadata:    metadataJSON(ctx.Metadata),
	}
	if f, ok := ctx.Artifact.(*File); ok && f != nil {
		rec.RequiresPython = f.RequiresPython
		rec.Yanked = f.Yanked.Bool()
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
	a.writeFile(w, body)
}

// trackDownload emits a dependency download record for project-scoped requests.
// The tracker is nil on the dispatch-only path and the ProjectKey=="" short
// circuit returns before any allocation, so default-path traffic has zero
// overhead.
func (a *pypiAdapter) trackDownload(ctx *pipeline.PipelineContext, sha256 string) {
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

func (a *pypiAdapter) verifyOrEvict(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, expected string, body []byte) ([]byte, bool) {
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
	ctx.Tarball = nil // force the upstream middleware to re-fetch the file
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

func (a *pypiAdapter) fetchBytes(ctx *pipeline.PipelineContext, rp *project.Resolved) ([]byte, error) {
	if err := rp.Retrieval.Run(ctx); err != nil {
		return nil, err
	}
	if ctx.Tarball == nil {
		return nil, pipeline.ErrNoResolver
	}
	return ctx.Tarball.Bytes, nil
}

func (a *pypiAdapter) fetchErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		a.fail(w, r, http.StatusNotFound, "project or file not found upstream")
	case errors.Is(err, pipeline.ErrRejected):
		a.fail(w, r, http.StatusForbidden, "retrieval rejected", err)
	case errors.Is(err, pipeline.ErrNoResolver):
		a.fail(w, r, http.StatusBadGateway, "no retrieval middleware resolved the file", err)
	default:
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
	}
}

func (a *pypiAdapter) writeFile(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body) //nolint:gosec // G705: a proxy serves validated bytes by design
}

func (a *pypiAdapter) fail(w http.ResponseWriter, r *http.Request, code int, msg string, errs ...error) {
	if len(errs) > 0 && errs[0] != nil {
		a.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg, "err", errs[0].Error())
	} else {
		a.logger.Warn("request failed", "path", r.URL.Path, "status", code, "msg", msg)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	if len(errs) > 0 && errs[0] != nil {
		// Surface the underlying reason (e.g. the CVE IDs on a retrieval-rejected
		// deny) so clients see why the request failed, not just the short msg.
		msg += ": " + errs[0].Error()
	}
	_, _ = w.Write([]byte(msg + "\n")) //nolint:gosec // G705: plain-text error detail, not HTML
}

// baseURL returns scheme://host + this adapter's prefix, for rewriting file
// URLs so clients fetch files through the proxy.
func (a *pypiAdapter) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host + strings.TrimRight(a.prefix, "/")
}

// rewriteIndexJSON rewrites each file's url in a PEP 691 JSON index to
// <base>/files/<name>/<version>/<filename>, preserving every other field.
func rewriteIndexJSON(raw []byte, base, name string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	files, ok := doc["files"].([]any)
	if !ok {
		return json.Marshal(doc)
	}
	for _, f := range files {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		fn, _ := m["filename"].(string)
		ver, err := pypifilename.ParseVersion(fn)
		if err != nil || ver == "" {
			// Unparseable filename: still rewrite to the proxy route under the
			// sentinel version so no file keeps its upstream URL. handleFile
			// 404s these on the proxy side (issue #116).
			ver = unparseableVersion
		}
		m["url"] = base + "/files/" + name + "/" + ver + "/" + url.PathEscape(fn)
	}
	return json.Marshal(doc)
}

func metadataJSON(m map[string]any) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}
