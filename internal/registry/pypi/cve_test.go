package pypi

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
)

// TestCveCheckDeniesVulnerableThroughPipeline wires cve-check into the pypi
// pipeline and asserts a version OSV flags as vulnerable is rejected with 403 on
// the file route (full fetch -> validate -> reject path).
func TestCveCheckDeniesVulnerableThroughPipeline(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2026-0001", "summary": "arbitrary code execution"}},
		})
	}))
	defer osv.Close()

	dir := t.TempDir()
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &rawClient{project: proj, raw: raw, file: []byte("WHEEL")}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("cve-check", cve.Factory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(c))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: pyYamlNode("min_days: 0")}, // age gate off; only cve-check gates
		{Type: "cve-check", Params: pyYamlNode("endpoint: " + osv.URL)},
	})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: pyYamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, _ := reg.BuildMutation(nil)
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	var cache evicter
	if e, ok := retrieval.Head.(evicter); ok {
		cache = e
	}
	a := &pypiAdapter{
		prefix:     "/pypi",
		storage:    store,
		client:     c,
		validation: validation,
		retrieval:  retrieval,
		mutation:   mp,
		cache:      cache,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:        func() time.Time { return time.Now().UTC() },
	}
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != http.StatusForbidden {
		t.Fatalf("vulnerable version should be rejected with 403, got %d", code)
	}
}
