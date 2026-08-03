package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// fakeDependencyTracker records Tracked records; it never flushes to a DB.
type fakeDependencyTracker struct {
	mu      sync.Mutex
	records []project.DependencyRecord
}

func (f *fakeDependencyTracker) Track(rec project.DependencyRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
}
func (f *fakeDependencyTracker) Start(context.Context) error    { return nil }
func (f *fakeDependencyTracker) Shutdown(context.Context) error { return nil }

func (f *fakeDependencyTracker) all() []project.DependencyRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]project.DependencyRecord(nil), f.records...)
}

// newTestAdapterWithTracker is newTestAdapter plus a DependencyTracker; a nil
// tracker leaves the existing (untracked) behavior unchanged.
func newTestAdapterWithTracker(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store, tracker project.DependencyTracker) *npmAdapter {
	t.Helper()
	a := newTestAdapterWithGlobal(t, prefix, dir, minDays, client, store, nil)
	a.tracker = tracker
	return a
}

// acmeWarnAdapter builds an npmAdapter whose resolver maps project key "acme" to
// a cve-check warn override (the "acme warn" path from project_resolve_test) so
// a project-scoped request serves 200/TARBALL despite the global deny.
func acmeWarnAdapter(t *testing.T, tracker project.DependencyTracker) *npmAdapter {
	t.Helper()
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2026-0001", "summary": "arbitrary code execution"}},
		})
	}))
	t.Cleanup(osv.Close)

	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().Add(-30*24*time.Hour), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")}, // age gate off; only cve-check gates
		{Type: "cve-check", Params: yamlNode("endpoint: " + osv.URL)},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: yamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, err := reg.BuildMutation(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp}
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		global.Cache = e
	}

	seed := &seededProjectStore{cfgs: map[string]project.ProjectConfig{
		"acme": {
			Key: "acme",
			Registries: map[string]config.RegistryMiddlewareConfig{
				"npm": {
					Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("endpoint: " + osv.URL + "\nmode: warn")}},
				},
			},
		},
	}}
	resolver := project.NewResolver("npm", reg, seed, global)
	return &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		tracker:  tracker,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func TestNpmProjectDownloadTracked(t *testing.T) {
	tracker := &fakeDependencyTracker{}
	a := acmeWarnAdapter(t, tracker)
	srv := newTestServer(t, a)

	code, body := fetchTarball(t, srv.URL+"/npm/p/acme/testpkg/-/1.0.0")
	if code != http.StatusOK || string(body) != "TARBALL" {
		t.Fatalf("acme project path: code=%d body=%q want 200/TARBALL", code, body)
	}
	recs := tracker.all()
	if len(recs) != 1 {
		t.Fatalf("tracked %d records, want 1", len(recs))
	}
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("TARBALL")))
	got := recs[0]
	if got.ProjectKey != "acme" || got.Registry != "npm" || got.Pkg != "testpkg" ||
		got.Version != "1.0.0" || got.ArtifactID != "" || got.SHA256 != wantHash {
		t.Errorf("record = %+v", got)
	}
}

func TestNpmDefaultPathNotTracked(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	tracker := &fakeDependencyTracker{}
	a := newTestAdapterWithTracker(t, "/npm", dir, 0, client, store, tracker)
	srv := newTestServer(t, a)

	code, body := fetchTarball(t, srv.URL+"/npm/testpkg/-/1.0.0")
	if code != http.StatusOK || string(body) != "TARBALL" {
		t.Fatalf("default path: code=%d body=%q want 200/TARBALL", code, body)
	}
	if recs := tracker.all(); len(recs) != 0 {
		t.Fatalf("tracked %d records on default path, want 0 (ProjectKey==\"\" short-circuit)", len(recs))
	}
}
