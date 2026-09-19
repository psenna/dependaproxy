package oci

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/validation/pathallowlist"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

func init() { adapter.Register("oci", Factory) }

// manifestBlobGetter is the subset of *Client's behavior the adapter depends
// on, so tests can inject a fake instead of talking to a real registry.
type manifestBlobGetter interface {
	GetManifest(ctx context.Context, repoPath, ref string) (*ManifestResult, error)
	GetBlob(ctx context.Context, repoPath, digest string) ([]byte, string, error)
}

// ociUpstream is one configured, ready-to-serve upstream registry.
type ociUpstream struct {
	name       string
	client     manifestBlobGetter
	validation pipeline.ValidationPipeline
}

// ociAdapter is the type: oci Adapter: one instance mounted at the fixed
// prefix /v2, routing between its configured upstreams by the leading path
// segment of the requested repository name. See the design spec for why a
// single fixed prefix is required by the registry-v2 protocol.
type ociAdapter struct {
	prefix    string
	upstreams map[string]*ociUpstream
	log       *slog.Logger // nil-safe: every read of a.log guards for nil, matching e.g. malware.Middleware.Validate's pattern
}

// Factory builds the oci adapter from its RegistryConfig + shared Deps.
// Config-shape errors (wrong prefix, no upstreams, unknown middleware type)
// were already caught by config.Validate at load time; Factory re-derives
// nothing that Validate did not already guarantee, except building the
// per-upstream go-containerregistry client and validation pipeline.
func Factory(_ context.Context, cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	a, err := newAdapter(cfg.Prefix, cfg.Upstreams)
	if err != nil {
		return nil, err
	}
	a.log = deps.Logger
	return a, nil
}

// newAdapter is Factory's logic, split out so tests can build an adapter
// directly (with real go-containerregistry clients) and then swap in a
// fakeClient per upstream without going through the full Factory/Deps path.
func newAdapter(prefix string, upstreamCfgs []config.OCIUpstreamConfig) (*ociAdapter, error) {
	if strings.TrimRight(prefix, "/") != "/v2" {
		return nil, fmt.Errorf("oci: prefix must be \"/v2\" (got %q) -- the registry-v2 protocol fixes this root", prefix)
	}
	a := &ociAdapter{prefix: prefix, upstreams: map[string]*ociUpstream{}}
	for _, uc := range upstreamCfgs {
		client, err := NewClient(uc.Upstream)
		if err != nil {
			return nil, fmt.Errorf("oci upstream %q: %w", uc.Name, err)
		}
		reg := pipeline.NewRegistry()
		reg.RegisterValidation("path-allowlist", pathallowlist.Factory)
		validation, err := reg.BuildValidation(uc.Validation)
		if err != nil {
			return nil, fmt.Errorf("oci upstream %q: %w", uc.Name, err)
		}
		a.upstreams[uc.Name] = &ociUpstream{name: uc.Name, client: client, validation: validation}
	}
	return a, nil
}

// Prefix returns the fixed URL path prefix "/v2".
func (a *ociAdapter) Prefix() string { return a.prefix }

// Handler serves the registry-v2 routes (paths are relative to /v2 -- the
// server strips the prefix before dispatching, so a.serve sees "/" for the
// bare ping and "/docker/library/nginx/manifests/latest" for a pull).
func (a *ociAdapter) Handler() http.Handler { return http.HandlerFunc(a.serve) }

// InvalidateProjectCache is a no-op: oci has no per-project override support
// (the registry-v2 URL space has no room for a project-key segment without
// colliding with the upstream-name segment), matching the documented pattern
// for "adapters without a resolver."
func (a *ociAdapter) InvalidateProjectCache(string) {}

func (a *ociAdapter) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
		return
	}
	upstreamName, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !ok {
		writeError(w, http.StatusNotFound, CodeNameUnknown, "repository name not known to registry")
		return
	}
	u, ok := a.upstreams[upstreamName]
	if !ok {
		writeError(w, http.StatusNotFound, CodeNameUnknown, fmt.Sprintf("unknown upstream %q", upstreamName))
		return
	}
	a.route(w, r, u, rest)
}

// route dispatches a request already stripped of its upstream-name segment
// (rest is e.g. "library/nginx/manifests/latest").
func (a *ociAdapter) route(w http.ResponseWriter, r *http.Request, u *ociUpstream, rest string) {
	if name, ref, ok := cutSuffix(rest, "/manifests/"); ok {
		a.serveManifest(w, r, u, name, ref)
		return
	}
	if name, digest, ok := cutSuffix(rest, "/blobs/"); ok {
		a.serveBlob(w, r, u, name, digest)
		return
	}
	writeError(w, http.StatusNotFound, CodeNameUnknown, "not found")
}

// cutSuffix splits "<name><sep><ref>" on the LAST occurrence of sep (a
// repository name may itself contain "/", so this cannot use strings.Cut,
// which splits on the first occurrence). ok is false if sep does not appear,
// or if either side would be empty.
func cutSuffix(s, sep string) (name, ref string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i <= 0 {
		return "", "", false
	}
	name, ref = s[:i], s[i+len(sep):]
	if ref == "" {
		return "", "", false
	}
	return name, ref, true
}

func (a *ociAdapter) serveManifest(w http.ResponseWriter, r *http.Request, u *ociUpstream, repoPath, ref string) {
	ctx := pipeline.NewPipelineContext(r.Context(), a.log, "oci/"+u.name, repoPath, ref, "")
	if err := u.validation.Run(ctx); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}
	m, err := u.client.GetManifest(r.Context(), repoPath, ref)
	if err != nil {
		if a.log != nil {
			a.log.Warn("oci: upstream manifest fetch failed", "upstream", u.name, "repo", repoPath, "ref", ref, "err", err)
		}
		writeError(w, http.StatusNotFound, CodeManifestUnknown, err.Error())
		return
	}
	w.Header().Set("Docker-Content-Digest", m.Digest)
	w.Header().Set("Content-Type", m.MediaType)
	_, _ = w.Write(m.Bytes) //nolint:gosec // G705: a proxy writes upstream content by design
}

func (a *ociAdapter) serveBlob(w http.ResponseWriter, r *http.Request, u *ociUpstream, repoPath, digest string) {
	ctx := pipeline.NewPipelineContext(r.Context(), a.log, "oci/"+u.name, repoPath, digest, "")
	if err := u.validation.Run(ctx); err != nil {
		writeError(w, http.StatusForbidden, CodeDenied, err.Error())
		return
	}
	data, mediaType, err := u.client.GetBlob(r.Context(), repoPath, digest)
	if err != nil {
		if a.log != nil {
			a.log.Warn("oci: upstream blob fetch failed", "upstream", u.name, "repo", repoPath, "digest", digest, "err", err)
		}
		writeError(w, http.StatusNotFound, CodeBlobUnknown, err.Error())
		return
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", mediaType)
	_, _ = w.Write(data) //nolint:gosec // G705: a proxy writes upstream content by design
}
