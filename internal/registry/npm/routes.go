package npm

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// npmAdapter is the npm registry adapter. Pipelines are resolved per request
// scope (default or project) via the project resolver.
type npmAdapter struct {
	prefix   string
	storage  Store
	client   RegistryClient
	resolver *project.Resolver
	tracker  project.DependencyTracker // nil on the dispatch-only/default path
	logger   *slog.Logger
	now      func() time.Time
}

// Prefix returns the URL path prefix.
func (a *npmAdapter) Prefix() string { return a.prefix }

// Handler serves the npm routes (paths are relative to the prefix — the server
// strips the prefix before dispatching).
func (a *npmAdapter) Handler() http.Handler { return http.HandlerFunc(a.serve) }

// InvalidateProjectCache drops the cached Resolved pipelines for key so the
// next project-scoped request re-reads the project store.
func (a *npmAdapter) InvalidateProjectCache(key string) { a.resolver.Invalidate(key) }

func (a *npmAdapter) serve(w http.ResponseWriter, r *http.Request) {
	remaining, key := pipeline.ParseProjectPath(r.URL.Path)
	if key != "" {
		r = r.WithContext(pipeline.ContextWithProjectKey(r.Context(), key))
		r.URL.Path = remaining
	}
	if r.Method != http.MethodGet {
		a.fail(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	switch {
	case strings.Contains(r.URL.Path, "/-/"):
		a.handleTarball(w, r)
	default:
		a.handlePackument(w, r)
	}
}

// handlePackument proxies the upstream packument, rewriting each version's
// dist.tarball to point at the proxy (under this adapter's prefix).
func (a *npmAdapter) handlePackument(w http.ResponseWriter, r *http.Request) {
	pkg := strings.TrimPrefix(r.URL.Path, "/")
	if pkg == "" {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	raw, err := a.client.FetchPackumentRaw(r.Context(), pkg)
	if errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusNotFound, "package not found")
		return
	}
	if err != nil {
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
		return
	}
	rewritten, err := rewriteTarballs(raw, a.baseURL(r), pkg)
	if err != nil {
		a.fail(w, r, http.StatusInternalServerError, "rewrite packument", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(rewritten) //nolint:gosec // G705: a proxy writes upstream content by design
}

// handleTarball serves a tarball through the trust flow.
func (a *npmAdapter) handleTarball(w http.ResponseWriter, r *http.Request) {
	pkg, version, ok := parseTarballPath(r.URL.Path)
	if !ok {
		a.fail(w, r, http.StatusNotFound, "not found")
		return
	}
	ctx := pipeline.NewPipelineContext(r.Context(), a.logger, "npm", pkg, version, "")
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
	rec, err := a.storage.Get(ctx.Ctx, pkg, version)
	if err == nil {
		a.serveTrusted(w, r, ctx, rp, rec)
		return
	}
	if !errors.Is(err, ErrNotFound) {
		a.fail(w, r, http.StatusInternalServerError, "storage", err)
		return
	}
	a.serveUntrusted(w, r, ctx, rp, pkg, version)
}

func (a *npmAdapter) serveTrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, rec Record) {
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

func (a *npmAdapter) serveUntrusted(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, pkg, version string) {
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
	rec := Record{
		Name:           pkg,
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
func (a *npmAdapter) trackDownload(ctx *pipeline.PipelineContext, sha256 string) {
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

func (a *npmAdapter) verifyOrEvict(w http.ResponseWriter, r *http.Request, ctx *pipeline.PipelineContext, rp *project.Resolved, expected string, body []byte) ([]byte, bool) {
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
	ctx.Tarball = nil // force the upstream middleware to re-fetch the tarball
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

func (a *npmAdapter) fetchBytes(ctx *pipeline.PipelineContext, rp *project.Resolved) ([]byte, error) {
	if err := rp.Retrieval.Run(ctx); err != nil {
		return nil, err
	}
	if ctx.Tarball == nil {
		return nil, pipeline.ErrNoResolver
	}
	return ctx.Tarball.Bytes, nil
}

func (a *npmAdapter) fetchErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		a.fail(w, r, http.StatusNotFound, "package or version not found upstream")
	case errors.Is(err, pipeline.ErrRejected):
		a.fail(w, r, http.StatusForbidden, "retrieval rejected", err)
	case errors.Is(err, pipeline.ErrNoResolver):
		a.fail(w, r, http.StatusBadGateway, "no retrieval middleware resolved the package", err)
	default:
		a.fail(w, r, http.StatusBadGateway, "upstream error", err)
	}
}

func (a *npmAdapter) writeTarball(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body) //nolint:gosec // G705: a proxy serves validated bytes by design
}

func (a *npmAdapter) fail(w http.ResponseWriter, r *http.Request, code int, msg string, errs ...error) {
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

// baseURL returns scheme://host + this adapter's prefix, for rewriting
// dist.tarball URLs so clients fetch tarballs through the proxy.
func (a *npmAdapter) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host + strings.TrimRight(a.prefix, "/")
}

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

// parseTarballPath splits "<pkg>/-/<version>" into (pkg, version).
func parseTarballPath(p string) (pkg, version string, ok bool) {
	idx := strings.Index(p, "/-/")
	if idx <= 0 {
		return "", "", false
	}
	pkg = strings.TrimPrefix(p[:idx], "/")
	version = p[idx+3:]
	if pkg == "" || version == "" || strings.Contains(version, "/") {
		return "", "", false
	}
	// Accept the public-registry tarball filename format (<name>-<version>.tgz,
	// e.g. css-tools-4.5.0.tgz for @adobe/css-tools) in addition to the proxy's
	// own rewritten form (<version>, no .tgz / name prefix). The URLs produced
	// by `npm config replace-registry-host=always` (rewriting lockfile dist URLs
	// to this proxy) carry the public filename, which must normalize back to the
	// bare version for the upstream fetch and store lookup. Stripping the
	// "<name>-" prefix is safe: npm versions are semver, so a real version can
	// never begin with the package name followed by a hyphen.
	version = strings.TrimSuffix(version, ".tgz")
	if name := path.Base(pkg); strings.HasPrefix(version, name+"-") {
		version = strings.TrimPrefix(version, name+"-")
	}
	if version == "" {
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
