package pypi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/pypifilename"
	"github.com/psenna/dependaproxy/internal/registry/registryhttp"
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

	// upstreamAlias enables the /upstream/{host}/{path...} path-mirroring alias
	// route (issue #185); upstreamHosts is the same allowlist the upstream
	// client fetches under, used for a cheap inbound membership check.
	upstreamAlias bool
	upstreamHosts *registryhttp.Allowlist
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
	if a.upstreamAlias {
		mux.HandleFunc("GET /upstream/{host}/{path...}", a.handleUpstream)
	}
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

// handleFile serves a file through the trust flow (the /files/ route).
func (a *pypiAdapter) handleFile(w http.ResponseWriter, r *http.Request) {
	pkg := r.PathValue("name")
	version := r.PathValue("version")
	filename := r.PathValue("filename")
	if pkg == "" || version == "" || filename == "" {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	if strings.HasSuffix(filename, ".metadata") {
		a.fail(w, r, http.StatusNotFound, "metadata not served")
		return
	}
	v, err := pypifilename.ParseVersion(filename)
	if err != nil || v == "" {
		a.fail(w, r, http.StatusNotFound, "unparseable filename")
		return
	}
	// Security boundary (H1): the {version} path segment must equal the version
	// actually encoded in filename. This is the /files/-route path-segment
	// binding — serveArtifact re-derives the version from filename alone and
	// keys every version-keyed gate (cve-check, deny-list, provenance-verify,
	// the trust-store/cache key) on it, so without this compare a client could
	// request the real bytes of one version under an unrelated, clean-looking
	// version string in the URL.
	if v != version {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	a.serveArtifact(w, r, NormalizeName(pkg), filename)
}

// serveArtifact runs the full trust flow for one artifact of project `name`.
// The version is derived from `filename` here and nowhere else, so every
// version-keyed gate (cve-check, deny-list, provenance, the trust-store/cache
// key) is bound to the bytes actually served (H1) no matter which route called
// in. `name` must already be PEP 503 normalized (pypi.NormalizeName).
func (a *pypiAdapter) serveArtifact(w http.ResponseWriter, r *http.Request, name, filename string) {
	if name == "" || filename == "" {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	// PEP 658 metadata files (X.whl.metadata / X.tar.gz.metadata) are not listed
	// in the simple index and are not served by the proxy. 404 so pip falls back
	// to downloading the distribution and reading its metadata from it.
	if strings.HasSuffix(filename, ".metadata") {
		a.fail(w, r, http.StatusNotFound, "metadata not served")
		return
	}
	// Security boundary (issue #116): a filename that cannot be parsed to a
	// version is served by no route — the index rewrite maps it to the "_"
	// sentinel version, and this gate 404s it here. Re-parse the filename
	// itself (not the path version sentinel) so the two stay symmetric.
	version, err := pypifilename.ParseVersion(filename)
	if err != nil || version == "" {
		a.fail(w, r, http.StatusNotFound, "unparseable filename")
		return
	}
	ctx := pipeline.NewPipelineContext(r.Context(), a.logger, "pypi", name, version, filename)
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
	rec, err := a.storage.Get(ctx.Ctx, ctx.ProjectKey, name, version, filename)
	if err == nil {
		a.serveTrusted(w, r, ctx, rp, rec)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	a.serveUntrusted(w, r, ctx, rp, name, version, filename)
}

// handleUpstream serves an artifact addressed by its canonical upstream path
// (/upstream/{host}/{path...}), so a lockfile that bakes absolute artifact URLs
// (uv.lock, pdm.lock) can be converted to proxy URLs — and back — with a single
// reversible string substitution.
//
// This is an ALIAS FOR THE TRUST KEY, NOT A PASSTHROUGH. {path...} is routing
// decoration only: it is never fetched. The bytes are resolved exactly as
// /files/ resolves them — the PEP 691 index for the derived name, matched by
// filename — so this route can only name a (name, version, filename) triple
// that /files/ can already name.
func (a *pypiAdapter) handleUpstream(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	rest := r.PathValue("path")
	if host == "" || rest == "" {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	// Cheap inbound membership check against the SAME allowlist the upstream
	// client fetches under. NOT CheckURL: that does DNS + private-IP checks and
	// is for outbound fetches.
	if !a.upstreamHosts.Allows(host) {
		a.fail(w, r, http.StatusNotFound, "upstream host not allowlisted")
		return
	}
	// TODO(#185 follow-up): optional `verify_upstream_path` — when {path...}
	// matches packages/<2hex>/<2hex>/<60hex>/<filename>, that digest is the
	// blake2b-256 of the artifact; verifying it against the served bytes binds
	// the requested path to the bytes with a purely local check. It must run
	// after the sha256 anchor is established and before writeFile (i.e. inside
	// serveTrusted/serveUntrusted, via an expected-digest field threaded from
	// here), and fail with 502 like the integrity-mismatch path. Deliberately
	// out of scope here: the path prefix is decoration, and the sha256 trust
	// anchor already gates every byte served.
	filename := path.Base(rest)
	name, err := pypifilename.ParseName(filename)
	if err != nil || name == "" {
		a.fail(w, r, http.StatusNotFound, "unparseable filename")
		return
	}
	a.serveArtifact(w, r, NormalizeName(name), filename)
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
	// Security boundary (H2): a trust-store hit proves only that this exact
	// (project, name, version, filename) passed validation once before -- it
	// does not re-run guarddog/malware/provenance-verify. Re-run the deny-list
	// gate specifically, so a denial recorded after that validation (an
	// operator denylisting this exact sha256, or the deny-list rule wired to a
	// newly-published CVE) is not permanently bypassed by the cache.
	if dl, ok := rp.Validation.Find(denylist.Name); ok {
		ctx.Metadata["sha256"] = rec.Sha256
		err := dl.Validate(ctx)
		delete(ctx.Metadata, "sha256") // keep the persisted metadata blob byte-identical
		if err != nil {
			a.fail(w, r, http.StatusForbidden, "validation rejected", err)
			return
		}
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
	// Hash once, up front, so the validation chain (deny-list check/record) can
	// read it from ctx.Metadata instead of recomputing the full tarball.
	h, _, err := hash.Sha256Hex(bytes.NewReader(body))
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "hash", err)
		return
	}
	ctx.Metadata["sha256"] = h
	if err := rp.Validation.Run(ctx); err != nil {
		a.fail(w, r, http.StatusForbidden, "validation rejected", err)
		return
	}
	h, _ = ctx.Sha256FromMetadata()
	delete(ctx.Metadata, "sha256") // keep the persisted metadata blob byte-identical
	info, err := pypifilename.Parse(filename)
	if err != nil {
		// Defense-in-depth: handleFile gates on ParseVersion before this
		// point, so this branch is normally unreachable. 404 (not 500) so an
		// unparseable filename is never served as a valid artifact.
		a.fail(w, r, http.StatusNotFound, "parse filename", err)
		return
	}
	rec := Record{
		ProjectKey:  ctx.ProjectKey,
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
		// The proxy does not serve PEP 658 metadata files (X.whl.metadata), so
		// drop the advertisement to make pip download the distribution directly
		// and read its metadata from it. The JSON simple index advertises it as
		// data-dist-info-metadata (PEP 691); core-metadata is a legacy alias.
		delete(m, "data-dist-info-metadata")
		delete(m, "core-metadata")
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
