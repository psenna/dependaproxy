// Package admin implements the project-config admin API mounted by the server
// at /admin (behind the shared token auth). It reads and writes per-project
// middleware overrides in the project store and fans cache invalidation out to
// every registry adapter so project-scoped requests re-resolve immediately.
package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// keyRe matches the project-key characters allowed in URL path segments. The
// lone key "-" is additionally rejected below because the project-path parser
// (pipeline.ParseProjectPath) treats "-" as "not a project scope".
var keyRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// validKey reports whether key is a usable project key: non-empty, matches
// keyRe, and is not the reserved "-" segment.
func validKey(key string) bool {
	return key != "" && key != "-" && keyRe.MatchString(key)
}

// Invalidator drops a project's cached pipelines across all registries.
type Invalidator interface {
	Invalidate(key string)
}

// Handler is the admin HTTP handler. The server strips /admin before
// dispatching, so the routes are relative to /admin.
type Handler struct {
	store           project.Store
	depStore        project.DependencyStore
	invalidator     Invalidator
	knownRegistries map[string]bool
	logger          *slog.Logger
}

// New builds an admin Handler for the project store. depStore serves the
// per-project dependency download records; it may be nil when the server has no
// database (the dependencies route then reports the store unavailable). inv
// receives an Invalidate(key) call after every successful create/update/delete
// so the registry resolvers drop their cached pipelines for that project.
// knownRegistries lists the registry types configured on this instance (e.g.
// ["npm", "pypi"]).
func New(store project.Store, depStore project.DependencyStore, inv Invalidator, logger *slog.Logger, knownRegistries []string) *Handler {
	kr := make(map[string]bool, len(knownRegistries))
	for _, r := range knownRegistries {
		kr[r] = true
	}
	return &Handler{store: store, depStore: depStore, invalidator: inv, knownRegistries: kr, logger: logger}
}

// Handler returns the admin route mux. Routes use Go 1.22 method+path patterns.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /projects", h.create)
	mux.HandleFunc("GET /projects", h.list)
	mux.HandleFunc("GET /projects/{key}", h.get)
	mux.HandleFunc("PUT /projects/{key}", h.put)
	mux.HandleFunc("DELETE /projects/{key}", h.delete)
	mux.HandleFunc("GET /projects/{key}/dependencies", h.dependencies)
	return mux
}

// --- JSON request/response types ---

type projectReq struct {
	Key        string                 `json:"key,omitempty"`
	Registries map[string]registryReq `json:"registries"`
}

type registryReq struct {
	Validation []middlewareReq `json:"validation,omitempty"`
	Retrieval  []middlewareReq `json:"retrieval,omitempty"`
	Mutation   []middlewareReq `json:"mutation,omitempty"`
}

type middlewareReq struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// projectResp mirrors project.ProjectConfig for JSON encoding.
type projectResp struct {
	Key        string                  `json:"key"`
	Registries map[string]registryResp `json:"registries"`
}

type registryResp struct {
	Validation []middlewareResp `json:"validation,omitempty"`
	Retrieval  []middlewareResp `json:"retrieval,omitempty"`
	Mutation   []middlewareResp `json:"mutation,omitempty"`
}

type middlewareResp struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

// dependencyResp mirrors project.DependencyRecord for JSON encoding. ProjectKey
// is omitted: it is constant for the /projects/{key}/dependencies route.
type dependencyResp struct {
	Registry          string    `json:"registry"`
	Pkg               string    `json:"pkg"`
	Version           string    `json:"version"`
	ArtifactID        string    `json:"artifact_id"`
	SHA256            string    `json:"sha256"`
	FirstDownloadedAt time.Time `json:"first_downloaded_at"`
	LastDownloadedAt  time.Time `json:"last_downloaded_at"`
	DownloadCount     int64     `json:"download_count"`
}

// jsonToYAMLNode converts a JSON params object into a block-style yaml.Node the
// middleware factories can decode (config.Middleware.Params). A zero-length raw
// returns the zero node (params omitted). yaml.v3 parses JSON (YAML 1.2 is a
// superset); decoding into any and re-encoding normalizes the node to block
// style so params marshal as YAML (min_days: 0), not a JSON flow mapping.
func jsonToYAMLNode(raw json.RawMessage) (yaml.Node, error) {
	if len(raw) == 0 {
		return yaml.Node{}, nil
	}
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return yaml.Node{}, fmt.Errorf("params: %w", err)
	}
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return yaml.Node{}, fmt.Errorf("params: %w", err)
	}
	return n, nil
}

// --- handlers ---

// create handles POST /projects. The key comes from the request body.
func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var req projectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	key := req.Key
	if !validKey(key) {
		h.writeError(w, http.StatusBadRequest, "invalid project key")
		return
	}
	cfg, err := h.buildConfig(key, req.Registries)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.store.Get(r.Context(), key); err == nil {
		h.writeError(w, http.StatusConflict, fmt.Sprintf("project %q already exists", key))
		return
	} else if !errors.Is(err, project.ErrProjectNotFound) {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	if err := h.store.Put(r.Context(), cfg); err != nil {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	h.invalidator.Invalidate(key)
	h.writeConfig(w, http.StatusCreated, cfg)
}

// list handles GET /projects.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	cfgs, err := h.store.List(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"projects": toProjectResps(cfgs)})
}

// get handles GET /projects/{key}.
func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validKey(key) {
		h.writeError(w, http.StatusBadRequest, "invalid project key")
		return
	}
	cfg, err := h.store.Get(r.Context(), key)
	if errors.Is(err, project.ErrProjectNotFound) {
		h.writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	h.writeConfig(w, http.StatusOK, cfg)
}

// dependencies handles GET /projects/{key}/dependencies. It returns the project's
// recorded artifact downloads, optionally filtered by registry and package query
// params. An empty result (the project key has no records) is a 404.
func (h *Handler) dependencies(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validKey(key) {
		h.writeError(w, http.StatusBadRequest, "invalid project key")
		return
	}
	if h.depStore == nil {
		h.writeError(w, http.StatusInternalServerError, "dependency store unavailable")
		return
	}
	q := r.URL.Query()
	recs, err := h.depStore.List(r.Context(), key, project.DependencyListFilters{Registry: q.Get("registry"), Pkg: q.Get("pkg")})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "dependency store")
		return
	}
	if len(recs) == 0 {
		h.writeError(w, http.StatusNotFound, "no dependencies for project")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"dependencies": toDependencyResps(recs)})
}

// put handles PUT /projects/{key}: UPSERT. The path key is authoritative; a
// body key that differs from the path key is rejected.
func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validKey(key) {
		h.writeError(w, http.StatusBadRequest, "invalid project key")
		return
	}
	var req projectReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Key != "" && req.Key != key {
		h.writeError(w, http.StatusBadRequest, "key in body does not match path key")
		return
	}
	cfg, err := h.buildConfig(key, req.Registries)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, err = h.store.Get(r.Context(), key)
	switch {
	case errors.Is(err, project.ErrProjectNotFound):
		if err := h.store.Put(r.Context(), cfg); err != nil {
			h.writeError(w, http.StatusInternalServerError, "store project")
			return
		}
		h.invalidator.Invalidate(key)
		h.writeConfig(w, http.StatusCreated, cfg)
	case err != nil:
		h.writeError(w, http.StatusInternalServerError, "store project")
	default: // found -> replace
		if err := h.store.Put(r.Context(), cfg); err != nil {
			h.writeError(w, http.StatusInternalServerError, "store project")
			return
		}
		h.invalidator.Invalidate(key)
		h.writeConfig(w, http.StatusOK, cfg)
	}
}

// delete handles DELETE /projects/{key}.
func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validKey(key) {
		h.writeError(w, http.StatusBadRequest, "invalid project key")
		return
	}
	if _, err := h.store.Get(r.Context(), key); errors.Is(err, project.ErrProjectNotFound) {
		h.writeError(w, http.StatusNotFound, "project not found")
		return
	} else if err != nil {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	if err := h.store.Delete(r.Context(), key); err != nil {
		h.writeError(w, http.StatusInternalServerError, "store project")
		return
	}
	h.invalidator.Invalidate(key)
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// buildConfig validates the request's registry/middleware entries and converts
// them into a project.ProjectConfig ready for the store. Middleware params are
// NOT deep-validated against factories; that happens lazily on first Resolve.
func (h *Handler) buildConfig(key string, registries map[string]registryReq) (project.ProjectConfig, error) {
	cfg := project.ProjectConfig{Key: key, Registries: map[string]config.RegistryMiddlewareConfig{}}
	for name, rr := range registries {
		if name == "" || !h.knownRegistries[name] {
			return project.ProjectConfig{}, fmt.Errorf("unknown registry type %q", name)
		}
		rmc := config.RegistryMiddlewareConfig{}
		var err error
		if rmc.Validation, err = toConfigMiddlewares(rr.Validation); err != nil {
			return project.ProjectConfig{}, err
		}
		if rmc.Retrieval, err = toConfigMiddlewares(rr.Retrieval); err != nil {
			return project.ProjectConfig{}, err
		}
		if rmc.Mutation, err = toConfigMiddlewares(rr.Mutation); err != nil {
			return project.ProjectConfig{}, err
		}
		cfg.Registries[name] = rmc
	}
	return cfg, nil
}

func toConfigMiddlewares(ms []middlewareReq) ([]config.Middleware, error) {
	if len(ms) == 0 {
		return nil, nil
	}
	out := make([]config.Middleware, 0, len(ms))
	for _, m := range ms {
		if m.Type == "" {
			return nil, fmt.Errorf("middleware type is required")
		}
		n, err := jsonToYAMLNode(m.Params)
		if err != nil {
			return nil, err
		}
		out = append(out, config.Middleware{Type: m.Type, Params: n})
	}
	return out, nil
}

func toDependencyResps(recs []project.DependencyRecord) []dependencyResp {
	out := make([]dependencyResp, 0, len(recs))
	for _, r := range recs {
		out = append(out, dependencyResp{
			Registry:          r.Registry,
			Pkg:               r.Pkg,
			Version:           r.Version,
			ArtifactID:        r.ArtifactID,
			SHA256:            r.SHA256,
			FirstDownloadedAt: r.FirstDownloadedAt,
			LastDownloadedAt:  r.LastDownloadedAt,
			DownloadCount:     r.DownloadCount,
		})
	}
	return out
}

func toProjectResps(cfgs []project.ProjectConfig) []projectResp {
	out := make([]projectResp, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, toProjectResp(c))
	}
	return out
}

func toProjectResp(cfg project.ProjectConfig) projectResp {
	out := projectResp{Key: cfg.Key, Registries: map[string]registryResp{}}
	for name, rmc := range cfg.Registries {
		rr := registryResp{
			Validation: toMiddlewareResps(rmc.Validation),
			Retrieval:  toMiddlewareResps(rmc.Retrieval),
			Mutation:   toMiddlewareResps(rmc.Mutation),
		}
		out.Registries[name] = rr
	}
	return out
}

func toMiddlewareResps(ms []config.Middleware) []middlewareResp {
	if len(ms) == 0 {
		return nil
	}
	out := make([]middlewareResp, 0, len(ms))
	for _, m := range ms {
		mr := middlewareResp{Type: m.Type}
		if !m.Params.IsZero() {
			var v any
			if err := m.Params.Decode(&v); err == nil {
				if b, err := json.Marshal(v); err == nil {
					mr.Params = b
				}
			}
		}
		out = append(out, mr)
	}
	return out
}

func (h *Handler) writeConfig(w http.ResponseWriter, code int, cfg project.ProjectConfig) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(toProjectResp(cfg))
}

func (h *Handler) writeError(w http.ResponseWriter, code int, reason string) {
	if h.logger != nil {
		h.logger.Warn("admin request failed", "status", code, "reason", reason)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}
