package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// fakeStore is an in-memory project.Store recording Put/Delete counts.
type fakeStore struct {
	mu      sync.Mutex
	cfgs    map[string]project.ProjectConfig
	puts    int
	gets    int
	deletes int
}

func newFakeStore() *fakeStore {
	return &fakeStore{cfgs: map[string]project.ProjectConfig{}}
}

func (s *fakeStore) Get(_ context.Context, key string) (project.ProjectConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if c, ok := s.cfgs[key]; ok {
		return c, nil
	}
	return project.ProjectConfig{}, project.ErrProjectNotFound
}

func (s *fakeStore) Put(_ context.Context, cfg project.ProjectConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	s.cfgs[cfg.Key] = cfg
	return nil
}

func (s *fakeStore) List(_ context.Context) ([]project.ProjectConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.cfgs))
	for k := range s.cfgs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]project.ProjectConfig, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.cfgs[k])
	}
	return out, nil
}

func (s *fakeStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	delete(s.cfgs, key)
	return nil
}

func (s *fakeStore) putCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

func (s *fakeStore) deleteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletes
}

// fakeInvalidator records Invalidate calls.
type fakeInvalidator struct {
	mu   sync.Mutex
	keys []string
}

func (f *fakeInvalidator) Invalidate(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
}

func (f *fakeInvalidator) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.keys {
		if k == key {
			return true
		}
	}
	return false
}

func (f *fakeInvalidator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

// fakeDependencyStore is an in-memory project.DependencyStore recording the last
// List call and returning configured records/errors.
type fakeDependencyStore struct {
	mu        sync.Mutex
	recs      []project.DependencyRecord
	gotKey    string
	gotFilt   project.DependencyListFilters
	listErr   error
	listCalls int
}

func (f *fakeDependencyStore) UpsertBatch(context.Context, []project.DependencyRecord) error {
	return nil
}

func (f *fakeDependencyStore) List(_ context.Context, key string, fl project.DependencyListFilters) ([]project.DependencyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotKey = key
	f.gotFilt = fl
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.recs, nil
}

// newTestHandler returns a handler wired with a fresh fake store, a recording
// invalidator, a fake dependency store, and known registry types ["npm", "pypi"].
func newTestHandler() (*fakeStore, *fakeInvalidator, *fakeDependencyStore, http.Handler) {
	store := newFakeStore()
	inv := &fakeInvalidator{}
	dep := &fakeDependencyStore{}
	logger := slog.New(slog.DiscardHandler)
	return store, inv, dep, New(store, dep, inv, logger, []string{"npm", "pypi"}).Handler()
}

func doJSON(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestJSONToYAMLNodeRoundTrip(t *testing.T) {
	n, err := jsonToYAMLNode(json.RawMessage(`{"min_days":0}`))
	if err != nil {
		t.Fatalf("jsonToYAMLNode: %v", err)
	}
	out, err := yaml.Marshal(&n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.TrimSpace(string(out)) != "min_days: 0" {
		t.Errorf("round trip = %q, want %q", out, "min_days: 0\n")
	}
}

func TestJSONToYAMLNodeEmpty(t *testing.T) {
	n, err := jsonToYAMLNode(nil)
	if err != nil {
		t.Fatalf("jsonToYAMLNode: %v", err)
	}
	if !n.IsZero() {
		t.Error("empty params must yield the zero node")
	}
}

func TestAdminCreate(t *testing.T) {
	store, inv, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPost, "/projects", `{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"mode":"warn"}}]}}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("code=%d want 201, body=%s", rr.Code, rr.Body.String())
	}
	if store.putCount() != 1 {
		t.Errorf("puts=%d want 1", store.putCount())
	}
	if !inv.has("acme") {
		t.Errorf("invalidator should have received acme, got %v", inv.keys)
	}
	store.mu.Lock()
	cfg, ok := store.cfgs["acme"]
	store.mu.Unlock()
	if !ok {
		t.Fatal("acme not stored")
	}
	if cfg.Key != "acme" {
		t.Errorf("stored key=%q want acme", cfg.Key)
	}
	if len(cfg.Registries["npm"].Validation) != 1 {
		t.Errorf("validation chain len=%d want 1", len(cfg.Registries["npm"].Validation))
	}
}

func TestAdminCreateDuplicate(t *testing.T) {
	store, inv, _, h := newTestHandler()
	store.cfgs["acme"] = project.ProjectConfig{Key: "acme"}
	rr := doJSON(h, http.MethodPost, "/projects", `{"key":"acme"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("code=%d want 409, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "already exists") {
		t.Errorf("body=%s", rr.Body.String())
	}
	if store.putCount() != 0 {
		t.Errorf("puts=%d want 0", store.putCount())
	}
	if inv.count() != 0 {
		t.Errorf("invalidator should not be called, got %v", inv.keys)
	}
}

func TestAdminList(t *testing.T) {
	store, _, _, h := newTestHandler()
	store.cfgs["zeta"] = project.ProjectConfig{Key: "zeta"}
	store.cfgs["acme"] = project.ProjectConfig{Key: "acme", Registries: map[string]config.RegistryMiddlewareConfig{
		"npm": {Validation: []config.Middleware{{Type: "cve-check"}}},
	}}
	rr := doJSON(h, http.MethodGet, "/projects", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Projects []projectResp `json:"projects"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Projects) != 2 {
		t.Fatalf("projects=%d want 2", len(resp.Projects))
	}
	if resp.Projects[0].Key != "acme" || resp.Projects[1].Key != "zeta" {
		t.Errorf("order = [%q %q], want [acme zeta]", resp.Projects[0].Key, resp.Projects[1].Key)
	}
	if len(resp.Projects[0].Registries["npm"].Validation) != 1 {
		t.Errorf("validation len=%d want 1", len(resp.Projects[0].Registries["npm"].Validation))
	}
}

func TestAdminGet(t *testing.T) {
	store, _, _, h := newTestHandler()
	store.cfgs["acme"] = project.ProjectConfig{Key: "acme", Registries: map[string]config.RegistryMiddlewareConfig{
		"npm": {Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("mode: warn")}}},
	}}
	rr := doJSON(h, http.MethodGet, "/projects/acme", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	var resp projectResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Key != "acme" {
		t.Errorf("key=%q want acme", resp.Key)
	}
	if len(resp.Registries["npm"].Validation) != 1 || resp.Registries["npm"].Validation[0].Type != "cve-check" {
		t.Errorf("validation=%+v", resp.Registries["npm"].Validation)
	}
}

func TestAdminGetNotFound(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodGet, "/projects/nope", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d want 404", rr.Code)
	}
}

func TestAdminPutUpsertCreate(t *testing.T) {
	store, inv, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPut, "/projects/acme", `{"registries":{"npm":{}}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("code=%d want 201, body=%s", rr.Code, rr.Body.String())
	}
	if store.putCount() != 1 {
		t.Errorf("puts=%d want 1", store.putCount())
	}
	if !inv.has("acme") {
		t.Errorf("invalidator should have received acme, got %v", inv.keys)
	}
}

func TestAdminPutUpsertReplace(t *testing.T) {
	store, inv, _, h := newTestHandler()
	store.cfgs["acme"] = project.ProjectConfig{Key: "acme"}
	rr := doJSON(h, http.MethodPut, "/projects/acme", `{"registries":{"npm":{}}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	if store.putCount() != 1 {
		t.Errorf("puts=%d want 1", store.putCount())
	}
	if !inv.has("acme") {
		t.Errorf("invalidator should have received acme, got %v", inv.keys)
	}
}

func TestAdminDelete(t *testing.T) {
	store, inv, _, h := newTestHandler()
	store.cfgs["acme"] = project.ProjectConfig{Key: "acme"}
	rr := doJSON(h, http.MethodDelete, "/projects/acme", "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code=%d want 204, body=%s", rr.Code, rr.Body.String())
	}
	if store.deleteCount() != 1 {
		t.Errorf("deletes=%d want 1", store.deleteCount())
	}
	if !inv.has("acme") {
		t.Errorf("invalidator should have received acme, got %v", inv.keys)
	}
}

func TestAdminDeleteNotFound(t *testing.T) {
	store, inv, _, h := newTestHandler()
	rr := doJSON(h, http.MethodDelete, "/projects/nope", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d want 404", rr.Code)
	}
	if store.deleteCount() != 0 {
		t.Errorf("deletes=%d want 0", store.deleteCount())
	}
	if inv.count() != 0 {
		t.Errorf("invalidator should not be called, got %v", inv.keys)
	}
}

func TestAdminMalformedJSON(t *testing.T) {
	store, inv, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPost, "/projects", `{not json`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400", rr.Code)
	}
	if store.putCount() != 0 || inv.count() != 0 {
		t.Error("malformed JSON must not write or invalidate")
	}
}

func TestAdminBadKey(t *testing.T) {
	for _, tc := range []struct {
		key  string
		body string
	}{
		{"bad key!", `{"key":"bad key!"}`},
		{"", `{"key":""}`},
		{"-", `{"key":"-"}`},
		{"bad/key", `{"key":"bad/key"}`},
	} {
		_, _, _, h := newTestHandler()
		rr := doJSON(h, http.MethodPost, "/projects", tc.body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("key %q: code=%d want 400, body=%s", tc.key, rr.Code, rr.Body.String())
		}
	}
}

func TestAdminUnknownRegistryType(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPost, "/projects", `{"key":"acme","registries":{"unknownreg":{}}}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400, body=%s", rr.Code, rr.Body.String())
	}
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errResp.Error != `unknown registry type "unknownreg"` {
		t.Errorf("error=%q", errResp.Error)
	}
}

func TestAdminMiddlewareNoType(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPost, "/projects", `{"key":"acme","registries":{"npm":{"validation":[{"params":{"mode":"warn"}}]}}}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "middleware type is required") {
		t.Errorf("body=%s", rr.Body.String())
	}
}

func TestAdminPutKeyMismatch(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPut, "/projects/acme", `{"key":"other"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "key in body does not match path key") {
		t.Errorf("body=%s", rr.Body.String())
	}
}

func TestAdminParamsBridge(t *testing.T) {
	store, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodPost, "/projects", `{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"min_days":0}}]}}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("code=%d want 201, body=%s", rr.Code, rr.Body.String())
	}
	store.mu.Lock()
	cfg, ok := store.cfgs["acme"]
	store.mu.Unlock()
	if !ok {
		t.Fatal("acme not stored")
	}
	rmc, ok := cfg.Registries["npm"]
	if !ok {
		t.Fatal("npm registry entry missing")
	}
	if len(rmc.Validation) != 1 {
		t.Fatalf("validation len=%d want 1", len(rmc.Validation))
	}
	if rmc.Validation[0].Params.IsZero() {
		t.Error("params node should be non-null")
	}
	var pr struct {
		MinDays int `yaml:"min_days"`
	}
	if err := rmc.Validation[0].Params.Decode(&pr); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if pr.MinDays != 0 {
		t.Errorf("min_days=%d want 0", pr.MinDays)
	}
}

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	if len(n.Content) > 0 {
		return *n.Content[0]
	}
	return n
}

func TestAdminDependenciesList(t *testing.T) {
	_, _, dep, h := newTestHandler()
	now := time.Now().UTC()
	dep.recs = []project.DependencyRecord{
		{ProjectKey: "acme", Registry: "npm", Pkg: "lodash", Version: "1.0.0", ArtifactID: "lodash-1.0.0.tgz",
			SHA256: "abc", FirstDownloadedAt: now.Add(-2 * time.Hour), LastDownloadedAt: now.Add(-time.Hour), DownloadCount: 3},
		{ProjectKey: "acme", Registry: "pypi", Pkg: "reqs", Version: "2.0", ArtifactID: "reqs-2.0.tar.gz",
			SHA256: "def", FirstDownloadedAt: now.Add(-time.Hour), LastDownloadedAt: now, DownloadCount: 1},
	}
	rr := doJSON(h, http.MethodGet, "/projects/acme/dependencies", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type=%q want application/json", ct)
	}
	var resp struct {
		Dependencies []dependencyResp `json:"dependencies"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Dependencies) != 2 {
		t.Fatalf("dependencies=%d want 2, body=%s", len(resp.Dependencies), rr.Body.String())
	}
	d0, d1 := resp.Dependencies[0], resp.Dependencies[1]
	if d0.Registry != "npm" || d0.Pkg != "lodash" || d0.Version != "1.0.0" ||
		d0.ArtifactID != "lodash-1.0.0.tgz" || d0.SHA256 != "abc" || d0.DownloadCount != 3 {
		t.Errorf("row0=%+v", d0)
	}
	if !d0.FirstDownloadedAt.Equal(dep.recs[0].FirstDownloadedAt) || !d0.LastDownloadedAt.Equal(dep.recs[0].LastDownloadedAt) {
		t.Errorf("row0 times=%s/%s want %s/%s", d0.FirstDownloadedAt, d0.LastDownloadedAt, dep.recs[0].FirstDownloadedAt, dep.recs[0].LastDownloadedAt)
	}
	if d1.Registry != "pypi" || d1.Pkg != "reqs" || d1.Version != "2.0" || d1.SHA256 != "def" || d1.DownloadCount != 1 {
		t.Errorf("row1=%+v", d1)
	}
}

func TestAdminDependenciesEmpty404(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodGet, "/projects/acme/dependencies", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d want 404, body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminDependenciesFilters(t *testing.T) {
	_, _, dep, h := newTestHandler()
	dep.recs = []project.DependencyRecord{{ProjectKey: "acme", Registry: "npm", Pkg: "lodash", Version: "1.0.0"}}
	rr := doJSON(h, http.MethodGet, "/projects/acme/dependencies?registry=npm&pkg=lodash", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d want 200, body=%s", rr.Code, rr.Body.String())
	}
	dep.mu.Lock()
	defer dep.mu.Unlock()
	if dep.gotKey != "acme" {
		t.Errorf("gotKey=%q want acme", dep.gotKey)
	}
	if dep.gotFilt.Registry != "npm" || dep.gotFilt.Pkg != "lodash" {
		t.Errorf("gotFilt=%+v want {npm lodash}", dep.gotFilt)
	}
	if dep.listCalls != 1 {
		t.Errorf("listCalls=%d want 1", dep.listCalls)
	}
}

func TestAdminDependenciesBadKey(t *testing.T) {
	_, _, _, h := newTestHandler()
	rr := doJSON(h, http.MethodGet, "/projects/bad%20key!/dependencies", "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code=%d want 400, body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid project key") {
		t.Errorf("body=%s", rr.Body.String())
	}
}

func TestAdminDependenciesStoreError(t *testing.T) {
	_, _, dep, h := newTestHandler()
	dep.listErr = errors.New("boom")
	rr := doJSON(h, http.MethodGet, "/projects/acme/dependencies", "")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("code=%d want 500, body=%s", rr.Code, rr.Body.String())
	}
}
