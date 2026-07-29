package pypi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/pypifilename"
)

// evicter is implemented by the cache middleware (localcache.Middleware).
type evicter interface {
	Evict(ctx *pipeline.PipelineContext) error
}

// pypiAdapter is the PyPI registry adapter.
type pypiAdapter struct {
	prefix     string
	storage    Store
	client     RegistryClient
	validation pipeline.ValidationPipeline
	retrieval  pipeline.RetrievalPipeline
	mutation   pipeline.MutationPipeline
	cache      evicter
	logger     *slog.Logger
	now        func() time.Time
}

// Prefix returns the URL path prefix.
func (a *pypiAdapter) Prefix() string { return a.prefix }

// Handler serves the PyPI routes (paths are relative to the prefix — the server
// strips the prefix before dispatching).
func (a *pypiAdapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /simple/{name}/", a.handleIndex)
	mux.HandleFunc("GET /files/{name}/{version}/{filename}", a.handleFile)
	return mux
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
	ctx := pipeline.NewPipelineContext(r.Context(), a.logger, "pypi", pkg, version, filename)
	if err := a.mutation.RunPreFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation prefetch", err)
		return
	}
	rec, err := a.storage.Get(ctx.Ctx, pkg, version, filename)
	if err == nil {
		a.serveTrusted(w, r, ctx, rec)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	a.serveUntrusted(w, r, ctx, pkg, version, filename)
}

func (a *pypiAdapter) serveTrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rec Record) {
	body, err := a.fetchBytes(ctx)
	if err != nil {
		a.fetchErr(w, r, err)
		return
	}
	body, ok := a.verifyOrEvict(w, r, ctx, rec.Sha256, body)
	if !ok {
		return
	}
	if err := a.mutation.RunPostFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	a.writeFile(w, body)
}

func (a *pypiAdapter) serveUntrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, pkg, version, filename string) {
	body, err := a.fetchBytes(ctx)
	if err != nil {
		a.fetchErr(w, r, err)
		return
	}
	if err := a.validation.Run(ctx); err != nil {
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
		a.fail(w, r, http.StatusInternalServerError, "parse filename", err)
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
	if err := a.mutation.RunPostFetch(ctx); err != nil {
		a.fail(w, r, http.StatusInternalServerError, "mutation postfetch", err)
		return
	}
	a.writeFile(w, body)
}

func (a *pypiAdapter) verifyOrEvict(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, expected string, body []byte) ([]byte, bool) {
	ok, _, err := hash.VerifyHex(expected, bytes.NewReader(body))
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "verify hash", err)
		return nil, false
	}
	if ok {
		return body, true
	}
	if a.cache != nil {
		_ = a.cache.Evict(ctx)
	}
	ctx.Tarball = nil // force the upstream middleware to re-fetch the file
	refetched, err := a.fetchBytes(ctx)
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

func (a *pypiAdapter) fetchBytes(ctx *pipeline.PipelineContext) ([]byte, error) {
	if err := a.retrieval.Run(ctx); err != nil {
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
	_, _ = w.Write([]byte(msg + "\n"))
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
			continue
		}
		m["url"] = base + "/files/" + name + "/" + ver + "/" + fn
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
