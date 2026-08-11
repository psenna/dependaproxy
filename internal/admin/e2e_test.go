package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	_ "github.com/psenna/dependaproxy/internal/registry/npm" // register npm adapter
	"github.com/psenna/dependaproxy/internal/server"
	"github.com/psenna/dependaproxy/internal/storage/db"
	"gopkg.in/yaml.v3"
)

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

// getPath performs an authed GET and returns (status, body).
func getPath(base, path, auth string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, base+path, nil) //nolint:gosec // G704: test URL
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test URL
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// doAdmin performs an authed admin API request and returns (status, body).
func doAdmin(base, method, path, body, auth string) (int, string) {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, base+path, rdr) //nolint:gosec // G704: test URL
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test URL
	if err != nil {
		return 0, ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestAdminE2EInvalidation proves the admin API drives live project-scoped
// pipelines and that create/update/delete invalidate the per-adapter resolver
// cache. It uses DISTINCT package names per step (alpha/beta/gamma/delta) so the
// npm validated-packages trust store never short-circuits validation: each step
// goes through serveUntrusted and actually runs the configured validation chain,
// making the deny/warn outcome attributable to the project pipeline, not to a
// cached trust record.
func TestAdminE2EInvalidation(t *testing.T) {
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping admin e2e")
	}

	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Fake npm upstream: serves a packument for ANY package name (the client
	// fetches <upstream>/<pkg>) plus one shared tarball endpoint.
	var npmTarballURL string
	npmMux := http.NewServeMux()
	npmMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pkg := strings.TrimPrefix(r.URL.Path, "/")
		if pkg == "tarball.tgz" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "TARBALL")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		packument := fmt.Sprintf(`{"name":%q,"versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":%q,"integrity":"sha512-x"}}},"time":{"1.0.0":%q},"dist-tags":{"latest":"1.0.0"}}`,
			pkg, npmTarballURL, time.Now().AddDate(0, 0, -30).Format(time.RFC3339Nano))
		_, _ = io.WriteString(w, packument) //nolint:gosec // G705: a proxy writes upstream content by design
	})
	fakeNpm := httptest.NewServer(npmMux)
	t.Cleanup(fakeNpm.Close)
	npmTarballURL = fakeNpm.URL + "/tarball.tgz"

	// Fake OSV: always reports a vulnerability.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2021-1234", "summary": "test vuln"}},
		})
	}))
	t.Cleanup(osvSrv.Close)

	cacheDir := t.TempDir()
	cfg := &config.Config{
		Auth:    config.Auth{Token: "tok", AdminToken: "admintok"},
		Storage: config.Storage{Type: "postgres", DSN: dsn},
		Log:     config.Log{Level: "warn", Format: "json"},
		Registries: []config.RegistryConfig{
			{Type: "npm", Prefix: "/npm", Upstream: fakeNpm.URL,
				Validation: []config.Middleware{
					{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
					{Type: "cve-check", Params: yamlNode("endpoint: " + osvSrv.URL + "\nmode: deny")},
				},
				Retrieval: []config.Middleware{
					{Type: "local-disk-cache", Params: yamlNode("path: " + filepath.Join(cacheDir, "npm"))},
					{Type: "upstream-registry"},
				}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	srv, err := server.New(ctx, cfg, d)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// server.New applied the npm + project schemas; clean for an isolated run.
	for _, tbl := range []string{"projects", "npm_validated_packages", "project_dependencies"} {
		if _, err := d.ExecContext(ctx, "DELETE FROM "+tbl); err != nil { //nolint:gosec // G202: fixed internal constant
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	// 1. Baseline global deny: no project -> global cve-check deny -> 403.
	if code, _ := getPath(httpSrv.URL, "/npm/alpha/-/1.0.0", "tok"); code != http.StatusForbidden {
		t.Fatalf("baseline global deny: code=%d want 403", code)
	}

	// 2. Create project acme with npm validation = cve-check warn -> 201.
	createBody := fmt.Sprintf(`{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"endpoint":%q,"mode":"warn"}}]}}}`, osvSrv.URL)
	code, respBody := doAdmin(httpSrv.URL, http.MethodPost, "/admin/projects", createBody, "admintok")
	if code != http.StatusCreated {
		t.Fatalf("create project: code=%d want 201, body=%s", code, respBody)
	}

	// 3. Use via project path (warn): distinct pkg beta -> 200 + TARBALL. This
	// warms the resolver cache for acme=warn.
	if code, got := getPath(httpSrv.URL, "/npm/p/acme/beta/-/1.0.0", "tok"); code != http.StatusOK || got != "TARBALL" {
		t.Fatalf("project warn: code=%d body=%q want 200 TARBALL", code, got)
	}

	// 4. Update project to deny -> 200 (must Invalidate("acme")).
	updateBody := fmt.Sprintf(`{"registries":{"npm":{"validation":[{"type":"cve-check","params":{"endpoint":%q,"mode":"deny"}}]}}}`, osvSrv.URL)
	code, respBody = doAdmin(httpSrv.URL, http.MethodPut, "/admin/projects/acme", updateBody, "admintok")
	if code != http.StatusOK {
		t.Fatalf("update project: code=%d want 200, body=%s", code, respBody)
	}

	// 5. Use via project path (now deny): distinct pkg gamma -> 403. If the PUT
	// had NOT invalidated the resolver cache, acme would still resolve to warn
	// and gamma would return 200. 403 proves the cache was dropped.
	if code, _ := getPath(httpSrv.URL, "/npm/p/acme/gamma/-/1.0.0", "tok"); code != http.StatusForbidden {
		t.Fatalf("project deny after update: code=%d want 403 (invalidation proof)", code)
	}

	// 6. Delete project -> 204 (Invalidate again).
	if code, _ := doAdmin(httpSrv.URL, http.MethodDelete, "/admin/projects/acme", "", "admintok"); code != http.StatusNoContent {
		t.Fatalf("delete project: code=%d want 204", code)
	}

	// 7. Fallback to global after delete: distinct pkg delta -> 403 (global deny).
	if code, _ := getPath(httpSrv.URL, "/npm/p/acme/delta/-/1.0.0", "tok"); code != http.StatusForbidden {
		t.Fatalf("fallback to global: code=%d want 403", code)
	}

	// 8. Unauthenticated admin calls -> 401 (admin token gate).
	if code, _ := doAdmin(httpSrv.URL, http.MethodPost, "/admin/projects", `{"key":"x"}`, ""); code != http.StatusUnauthorized {
		t.Fatalf("POST /admin/projects no auth: code=%d want 401", code)
	}
	if code, _ := doAdmin(httpSrv.URL, http.MethodGet, "/admin/projects", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/projects no auth: code=%d want 401", code)
	}

	// 9. Privilege separation: the PACKAGE token "tok" (valid for /npm) is
	// rejected on /admin — only the admin token can mutate configs.
	if code, _ := doAdmin(httpSrv.URL, http.MethodGet, "/admin/projects", "", "tok"); code != http.StatusUnauthorized {
		t.Fatalf("GET /admin/projects with package token: code=%d want 401", code)
	}
}

// depsRow mirrors the admin dependencies response shape for decoding.
type depsRow struct {
	Registry          string    `json:"registry"`
	Pkg               string    `json:"pkg"`
	Version           string    `json:"version"`
	ArtifactID        string    `json:"artifact_id"`
	SHA256            string    `json:"sha256"`
	FirstDownloadedAt time.Time `json:"first_downloaded_at"`
	LastDownloadedAt  time.Time `json:"last_downloaded_at"`
	DownloadCount     int64     `json:"download_count"`
}

func decodeDeps(t *testing.T, body string) []depsRow {
	t.Helper()
	var resp struct {
		Dependencies []depsRow `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode dependencies: %v (body=%s)", err, body)
	}
	return resp.Dependencies
}

// TestAdminE2EDependencies proves GET /admin/projects/{key}/dependencies serves
// the records the download tracker persists for project-scoped installs. The
// tracker flushes asynchronously (5s interval), so the endpoint is polled until
// the records appear rather than assuming a synchronous flush.
func TestAdminE2EDependencies(t *testing.T) {
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping admin e2e")
	}

	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Fake npm upstream: serves a packument for ANY package name (the client
	// fetches <upstream>/<pkg>) plus one shared tarball endpoint.
	var npmTarballURL string
	npmMux := http.NewServeMux()
	npmMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pkg := strings.TrimPrefix(r.URL.Path, "/")
		if pkg == "tarball.tgz" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, "TARBALL")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		packument := fmt.Sprintf(`{"name":%q,"versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":%q,"integrity":"sha512-x"}}},"time":{"1.0.0":%q},"dist-tags":{"latest":"1.0.0"}}`,
			pkg, npmTarballURL, time.Now().AddDate(0, 0, -30).Format(time.RFC3339Nano))
		_, _ = io.WriteString(w, packument) //nolint:gosec // G705: a proxy writes upstream content by design
	})
	fakeNpm := httptest.NewServer(npmMux)
	t.Cleanup(fakeNpm.Close)
	npmTarballURL = fakeNpm.URL + "/tarball.tgz"

	// Fake OSV: always reports a vulnerability, so cve-check warn lets installs
	// through while still exercising the validation chain.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulns": []map[string]any{{"id": "CVE-2021-1234", "summary": "test vuln"}},
		})
	}))
	t.Cleanup(osvSrv.Close)

	cacheDir := t.TempDir()
	cfg := &config.Config{
		Auth:    config.Auth{Token: "tok", AdminToken: "admintok"},
		Storage: config.Storage{Type: "postgres", DSN: dsn},
		Log:     config.Log{Level: "warn", Format: "json"},
		Registries: []config.RegistryConfig{
			{Type: "npm", Prefix: "/npm", Upstream: fakeNpm.URL,
				Validation: []config.Middleware{
					{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
					{Type: "cve-check", Params: yamlNode("endpoint: " + osvSrv.URL + "\nmode: deny")},
				},
				Retrieval: []config.Middleware{
					{Type: "local-disk-cache", Params: yamlNode("path: " + filepath.Join(cacheDir, "npm"))},
					{Type: "upstream-registry"},
				}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	srv, err := server.New(ctx, cfg, d)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// server.New applied the npm + project schemas; clean for an isolated run.
	for _, tbl := range []string{"projects", "npm_validated_packages", "project_dependencies"} {
		if _, err := d.ExecContext(ctx, "DELETE FROM "+tbl); err != nil { //nolint:gosec // G202: fixed internal constant
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	// 1. Create project acme with npm validation = cve-check warn -> 201.
	createBody := fmt.Sprintf(`{"key":"acme","registries":{"npm":{"validation":[{"type":"cve-check","params":{"endpoint":%q,"mode":"warn"}}]}}}`, osvSrv.URL)
	code, respBody := doAdmin(httpSrv.URL, http.MethodPost, "/admin/projects", createBody, "admintok")
	if code != http.StatusCreated {
		t.Fatalf("create project: code=%d want 201, body=%s", code, respBody)
	}

	// 2. Install TWO distinct packages under the project scope so two
	// dependency rows are recorded (distinct names avoid the trust-store
	// short-circuit, mirroring TestAdminE2EInvalidation).
	for _, pkg := range []string{"sbom-alpha", "sbom-beta"} {
		if code, got := getPath(httpSrv.URL, "/npm/p/acme/"+pkg+"/-/1.0.0", "tok"); code != http.StatusOK || got != "TARBALL" {
			t.Fatalf("install %s: code=%d body=%q want 200 TARBALL", pkg, code, got)
		}
	}

	// 3. Poll until the tracker has flushed both rows (async 5s flush; the
	// tracker field is unexported, so poll the endpoint).
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, respBody = getPath(httpSrv.URL, "/admin/projects/acme/dependencies", "admintok")
		if code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dependencies endpoint never returned 200 within 10s; last code=%d body=%s", code, respBody)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(respBody, "artifact_id") {
		t.Fatalf("artifact_id field missing from response: %s", respBody)
	}
	rows := decodeDeps(t, respBody)
	if len(rows) != 2 {
		t.Fatalf("dependencies=%d want 2, body=%s", len(rows), respBody)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		checkDepsRow(t, r)
		seen[r.Pkg] = true
	}
	if !seen["sbom-alpha"] || !seen["sbom-beta"] {
		t.Errorf("expected both sbom-alpha and sbom-beta, got %v", rows)
	}

	// 4. registry=npm filter -> 200, only npm rows.
	code, respBody = getPath(httpSrv.URL, "/admin/projects/acme/dependencies?registry=npm", "admintok")
	if code != http.StatusOK {
		t.Fatalf("filter registry=npm: code=%d want 200, body=%s", code, respBody)
	}
	assertAllRegistry(t, respBody, "npm")

	// 5. pkg=sbom-alpha filter -> 200, only that package.
	code, respBody = getPath(httpSrv.URL, "/admin/projects/acme/dependencies?pkg=sbom-alpha", "admintok")
	if code != http.StatusOK {
		t.Fatalf("filter pkg=sbom-alpha: code=%d want 200, body=%s", code, respBody)
	}
	assertAllPkg(t, respBody, "sbom-alpha")

	// 6. registry=pypi filter -> 404 (empty result for an unknown registry).
	if code, _ := getPath(httpSrv.URL, "/admin/projects/acme/dependencies?registry=pypi", "admintok"); code != http.StatusNotFound {
		t.Fatalf("filter registry=pypi: code=%d want 404", code)
	}
}

// checkDepsRow asserts the shape of one recorded npm dependency row.
func checkDepsRow(t *testing.T, r depsRow) {
	t.Helper()
	if r.Registry != "npm" {
		t.Errorf("registry=%q want npm", r.Registry)
	}
	if r.Version != "1.0.0" {
		t.Errorf("pkg %s: version=%q want 1.0.0", r.Pkg, r.Version)
	}
	if r.Pkg != "sbom-alpha" && r.Pkg != "sbom-beta" {
		t.Errorf("unexpected pkg=%q", r.Pkg)
	}
	if r.SHA256 == "" {
		t.Errorf("pkg %s: empty sha256", r.Pkg)
	}
	if r.FirstDownloadedAt.IsZero() || r.LastDownloadedAt.IsZero() {
		t.Errorf("pkg %s: zero download timestamps", r.Pkg)
	}
	if r.DownloadCount < 1 {
		t.Errorf("pkg %s: download_count=%d want >=1", r.Pkg, r.DownloadCount)
	}
}

// assertAllRegistry asserts every decoded row has the given registry.
func assertAllRegistry(t *testing.T, body, reg string) {
	t.Helper()
	rows := decodeDeps(t, body)
	if len(rows) == 0 {
		t.Fatalf("no rows for registry=%s", reg)
	}
	for _, r := range rows {
		if r.Registry != reg {
			t.Errorf("registry filter %s: row registry=%q want %s", reg, r.Registry, reg)
		}
	}
}

// assertAllPkg asserts every decoded row has the given package.
func assertAllPkg(t *testing.T, body, pkg string) {
	t.Helper()
	rows := decodeDeps(t, body)
	if len(rows) == 0 {
		t.Fatalf("no rows for pkg=%s", pkg)
	}
	for _, r := range rows {
		if r.Pkg != pkg {
			t.Errorf("pkg filter %s: row pkg=%q want %s", pkg, r.Pkg, pkg)
		}
	}
}
