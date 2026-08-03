package npm

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/cve"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// TestCveCheckDeniesVulnerableThroughPipeline wires cve-check into the npm
// pipeline (mirroring newTestAdapter) and asserts a version OSV flags as
// vulnerable is rejected with 403 on the tarball route — the full
// fetch -> validate -> reject path, not just the middleware unit.
func TestCveCheckDeniesVulnerableThroughPipeline(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2026-0001", "summary": "arbitrary code execution"}},
		})
	}))
	defer osv.Close()

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
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	a := &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != http.StatusForbidden {
		t.Fatalf("vulnerable version should be rejected with 403, got %d", code)
	}
}
