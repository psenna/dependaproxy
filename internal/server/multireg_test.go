package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	_ "github.com/psenna/dependaproxy/internal/registry/npm"  // register npm adapter
	_ "github.com/psenna/dependaproxy/internal/registry/pypi" // register pypi adapter
	"github.com/psenna/dependaproxy/internal/storage/db"
	"gopkg.in/yaml.v3"
)

// TestMultiRegistryE2E builds ONE server instance with BOTH npm and pypi
// adapters (real adapter factories, fake upstreams, real postgres storage),
// behind one shared auth token, and serves a validated package through each
// registry prefix in the same process.
func TestMultiRegistryE2E(t *testing.T) {
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping multi-registry e2e")
	}

	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Fake npm upstream. The packument's dist.tarball is set to the fake server
	// via a closure var resolved after the server is created.
	var npmTarballURL string
	npmMux := http.NewServeMux()
	npmMux.HandleFunc("/testpkg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"testpkg","versions":{"1.0.0":{"version":"1.0.0","dist":{"tarball":"`+npmTarballURL+`","integrity":"sha512-x"}}},"time":{"1.0.0":"`+time.Now().AddDate(0, 0, -30).Format(time.RFC3339Nano)+`"},"dist-tags":{"latest":"1.0.0"}}`)
	})
	npmMux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("NPM-TARBALL"))
	})
	fakeNpm := httptest.NewServer(npmMux)
	t.Cleanup(fakeNpm.Close)
	npmTarballURL = fakeNpm.URL + "/tarball.tgz"

	// Fake pypi upstream. The index file url is set via a closure var.
	var pyFileURL string
	pyMux := http.NewServeMux()
	pyMux.HandleFunc("/simple/testpkg/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = io.WriteString(w, `{"meta":{"api-version":"1.0"},"name":"testpkg","files":[{"filename":"testpkg-1.0.0-py3-none-any.whl","url":"`+pyFileURL+`","hashes":{},"requires-python":">=3.7","upload-time":"`+time.Now().AddDate(0, 0, -30).Format(time.RFC3339Nano)+`"}]}`)
	})
	pyMux.HandleFunc("/file.whl", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("PY-WHEEL"))
	})
	fakePy := httptest.NewServer(pyMux)
	t.Cleanup(fakePy.Close)
	pyFileURL = fakePy.URL + "/file.whl"

	cacheDir := t.TempDir()
	cfg := &config.Config{
		Auth:    config.Auth{Token: "tok"},
		Storage: config.Storage{Type: "postgres", DSN: dsn},
		Log:     config.Log{Level: "warn", Format: "json"},
		Registries: []config.RegistryConfig{
			{Type: "npm", Prefix: "/npm", Upstream: fakeNpm.URL,
				Validation: []config.Middleware{{Type: "min-publication-age", Params: yamlNode("min_days: 0")}},
				Retrieval:  []config.Middleware{{Type: "local-disk-cache", Params: yamlNode("path: " + filepath.Join(cacheDir, "npm"))}, {Type: "upstream-registry"}}},
			{Type: "pypi", Prefix: "/pypi", Upstream: fakePy.URL + "/simple",
				Validation: []config.Middleware{{Type: "min-publication-age", Params: yamlNode("min_days: 0")}},
				Retrieval:  []config.Middleware{{Type: "local-disk-cache", Params: yamlNode("path: " + filepath.Join(cacheDir, "pypi"))}, {Type: "upstream-registry"}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}

	srv, err := New(ctx, cfg, d)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// server.New applied both adapter schemas; now clean for an isolated run.
	tables := []string{"npm_validated_packages", "pypi_validated_files"}
	for _, tbl := range tables {
		_, err := d.ExecContext(ctx, "DELETE FROM "+tbl) //nolint:gosec // G202: tbl is a fixed internal constant
		if err != nil {
			t.Fatalf("clean %s: %v", tbl, err)
		}
	}

	// /healthz is open without auth.
	if code := getStatus(httpSrv.URL+"/healthz", ""); code != 200 {
		t.Fatalf("healthz: code=%d want 200", code)
	}
	// Both registries are protected by the shared token.
	if code := getStatus(httpSrv.URL+"/npm/testpkg", ""); code != 401 {
		t.Errorf("npm no-auth: code=%d want 401", code)
	}
	if code := getStatus(httpSrv.URL+"/pypi/simple/testpkg/", ""); code != 401 {
		t.Errorf("pypi no-auth: code=%d want 401", code)
	}

	// npm install flow through /npm/.
	npmCode, npmBody := fetchNpm(httpSrv.URL, "testpkg", "1.0.0", "tok")
	if npmCode != 200 || string(npmBody) != "NPM-TARBALL" {
		t.Fatalf("npm: code=%d body=%q", npmCode, npmBody)
	}
	// pypi install flow through /pypi/simple/.
	pyCode, pyBody := fetchPypi(httpSrv.URL, "testpkg", "tok")
	if pyCode != 200 || string(pyBody) != "PY-WHEEL" {
		t.Fatalf("pypi: code=%d body=%q", pyCode, pyBody)
	}

	// Both validated records persisted to the shared DB (per-adapter tables).
	var npmHash string
	if err := d.QueryRowContext(ctx, "SELECT validation_hash FROM npm_validated_packages WHERE name=$1 AND version=$2", "testpkg", "1.0.0").Scan(&npmHash); err != nil {
		t.Errorf("npm record not stored: %v", err)
	}
	var pyFilename string
	if err := d.QueryRowContext(ctx, "SELECT filename FROM pypi_validated_files WHERE name=$1 AND version=$2 AND filename=$3", "testpkg", "1.0.0", "testpkg-1.0.0-py3-none-any.whl").Scan(&pyFilename); err != nil {
		t.Errorf("pypi record not stored: %v", err)
	}

	// Cache files isolated per registry.
	if _, err := os.Stat(filepath.Join(cacheDir, "npm", "npm", "testpkg", "1.0.0.bin")); err != nil {
		t.Errorf("npm cache file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "pypi", "pypi", "testpkg", "1.0.0", "testpkg-1.0.0-py3-none-any.whl.bin")); err != nil {
		t.Errorf("pypi cache file missing: %v", err)
	}
}

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

func getStatus(url, auth string) int {
	req, _ := http.NewRequest(http.MethodGet, url, nil) //nolint:gosec // G704: test URL
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: test URL
	if err != nil {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func fetchNpm(base, pkg, ver, auth string) (int, []byte) {
	req, _ := http.NewRequest(http.MethodGet, base+"/npm/"+pkg, nil) //nolint:gosec // G704: test URL
	req.Header.Set("Authorization", "Bearer "+auth)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107
	if err != nil {
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return 0, nil
	}
	tb := doc["versions"].(map[string]any)[ver].(map[string]any)["dist"].(map[string]any)["tarball"].(string)
	r2, _ := http.NewRequest(http.MethodGet, tb, nil) //nolint:gosec // G704: test URL
	r2.Header.Set("Authorization", "Bearer "+auth)
	tr, err := http.DefaultClient.Do(r2) //nolint:gosec // G107
	if err != nil {
		return 0, nil
	}
	defer func() { _ = tr.Body.Close() }()
	b, _ := io.ReadAll(tr.Body)
	return tr.StatusCode, b
}

func fetchPypi(base, pkg, auth string) (int, []byte) {
	req, _ := http.NewRequest(http.MethodGet, base+"/pypi/simple/"+pkg+"/", nil) //nolint:gosec // G704: test URL
	req.Header.Set("Authorization", "Bearer "+auth)
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107
	if err != nil {
		return 0, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return 0, nil
	}
	url := doc["files"].([]any)[0].(map[string]any)["url"].(string)
	r2, _ := http.NewRequest(http.MethodGet, url, nil) //nolint:gosec // G704: test URL
	r2.Header.Set("Authorization", "Bearer "+auth)
	tr, err := http.DefaultClient.Do(r2) //nolint:gosec // G107
	if err != nil {
		return 0, nil
	}
	defer func() { _ = tr.Body.Close() }()
	b, _ := io.ReadAll(tr.Body)
	return tr.StatusCode, b
}
