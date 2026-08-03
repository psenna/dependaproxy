package goproxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/cverecheck"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/s3cache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/middleware/validation/malware"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
	"gopkg.in/yaml.v3"
)

// seededProjectStore is an in-memory project.Store with canned configs; unknown
// keys fall back to ErrProjectNotFound.
type seededProjectStore struct {
	cfgs map[string]project.ProjectConfig
}

func (s *seededProjectStore) Get(_ context.Context, key string) (project.ProjectConfig, error) {
	if c, ok := s.cfgs[key]; ok {
		return c, nil
	}
	return project.ProjectConfig{}, project.ErrProjectNotFound
}
func (s *seededProjectStore) Put(context.Context, project.ProjectConfig) error { return nil }
func (s *seededProjectStore) List(context.Context) ([]project.ProjectConfig, error) {
	return nil, nil
}
func (s *seededProjectStore) Delete(context.Context, string) error { return nil }

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

// TestProjectResolveDenyVsWarn drives the project resolver over the real goproxy
// routes: the default path inherits the global cve-check deny (403), a seeded
// project overriding validation to warn serves (200), and an unknown project
// falls back to the global deny (403). min-publication-age is present in the
// global chain but disabled (min_days: 0) so only cve-check gates.
func TestProjectResolveDenyVsWarn(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2026-0001", "summary": "arbitrary code execution"}},
		})
	}))
	defer osv.Close()

	dir := t.TempDir()
	store := newMemStore()
	client := newFakeClient()

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterValidation("malware-scan", malware.Factory)
	reg.RegisterRetrieval("cve-check-retrieval", cverecheck.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("s3-cache", s3cache.Factory)
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
				"goproxy": {
					Validation: []config.Middleware{{Type: "cve-check", Params: yamlNode("endpoint: " + osv.URL + "\nmode: warn")}},
				},
			},
		},
	}}

	resolver := project.NewResolver("goproxy", reg, seed, global)
	a := &goproxyAdapter{
		prefix:   "/goproxy",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
	srv := newTestServer(t, a)

	// Default path: the global deny rejects the vulnerable version.
	if code, _, _ := get(t, srv.URL+"/goproxy/"+testModuleEscaped+"/@v/"+testVersion+".zip"); code != http.StatusForbidden {
		t.Fatalf("default path: code=%d want 403 (global deny)", code)
	}
	// Unknown project: falls back to the global deny (before any request has
	// validated+stored the record — the trust store is global per name+version,
	// so this must run before the acme request below persists it).
	if code, _, _ := get(t, srv.URL+"/goproxy/p/unknown/"+testModuleEscaped+"/@v/"+testVersion+".zip"); code != http.StatusForbidden {
		t.Fatalf("unknown project path: code=%d want 403 (global deny fallback)", code)
	}
	// Project path: acme's warn override serves the vulnerable version.
	if code, _, body := get(t, srv.URL+"/goproxy/p/acme/"+testModuleEscaped+"/@v/"+testVersion+".zip"); code != http.StatusOK || string(body) != testZipBody {
		t.Fatalf("acme project path: code=%d body=%q want 200/%q", code, body, testZipBody)
	}
}
