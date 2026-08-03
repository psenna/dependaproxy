package stripscripts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

// makeTarGz builds a gzipped tar from files, stamping the given gzip header
// mtime so tests can prove the repacked output ignores the input gzip header.
// Entries are written in sorted name order so identical input maps produce
// byte-identical archives.
func makeTarGz(t *testing.T, files map[string]string, gzipModTime time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	zw.ModTime = gzipModTime
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

func npmCtx(data []byte) *pipeline.PipelineContext {
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", "testpkg", "1.0.0", "")
	ctx.Tarball = &pipeline.Tarball{Bytes: data}
	return ctx
}

// readPackageJSON gunzips+untars data and returns the decoded
// package/package.json map. Fails the test if absent.
func readPackageJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatal("package/package.json not found in tarball")
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "package/package.json" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			var pkg map[string]any
			if err := json.Unmarshal(body, &pkg); err != nil {
				t.Fatal(err)
			}
			return pkg
		}
	}
}

const pkgJSONWithInstallScripts = `{"name":"testpkg","version":"1.0.0","scripts":{"preinstall":"node pre.js","install":"node i.js","postinstall":"node post.js","test":"node test.js","build":"node build.js"},"dependencies":{"left-pad":"1.0.0"}}`

func TestPostFetchStripsInstallScripts(t *testing.T) {
	in := makeTarGz(t, map[string]string{"package/package.json": pkgJSONWithInstallScripts}, time.Unix(0, 0))
	ctx := npmCtx(in)
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatalf("PostFetch error: %v", err)
	}
	pkg := readPackageJSON(t, ctx.Tarball.Bytes)
	scripts, ok := pkg["scripts"].(map[string]any)
	if !ok {
		t.Fatalf("scripts missing after PostFetch: %v", pkg)
	}
	if len(scripts) != 2 {
		t.Fatalf("scripts = %v, want exactly {test,build}", scripts)
	}
	for _, key := range installScriptKeys {
		if _, exists := scripts[key]; exists {
			t.Errorf("install script %q still present after strip", key)
		}
	}
	if scripts["test"] != "node test.js" || scripts["build"] != "node build.js" {
		t.Errorf("non-install scripts not preserved: %v", scripts)
	}
	if pkg["name"] != "testpkg" || pkg["version"] != "1.0.0" {
		t.Errorf("name/version not preserved: %v", pkg)
	}
	deps, ok := pkg["dependencies"].(map[string]any)
	if !ok || deps["left-pad"] != "1.0.0" {
		t.Errorf("dependencies not preserved: %v", pkg["dependencies"])
	}
}

func TestPostFetchDeterminism(t *testing.T) {
	files := map[string]string{"package/package.json": pkgJSONWithInstallScripts, "package/index.js": "module.exports = 1\n"}
	// Same input, fresh ctx each time -> byte-identical output.
	in := makeTarGz(t, files, time.Unix(0, 0))
	ctx1 := npmCtx(in)
	ctx2 := npmCtx(in)
	if err := (Middleware{}).PostFetch(ctx1); err != nil {
		t.Fatal(err)
	}
	if err := (Middleware{}).PostFetch(ctx2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx1.Tarball.Bytes, ctx2.Tarball.Bytes) {
		t.Fatal("two PostFetch runs on the same input produced different bytes")
	}

	// Identical tar contents but different gzip header mtimes -> identical
	// output (proves the gzip-header ModTime/OS/Name fix).
	inA := makeTarGz(t, files, time.Unix(1000, 0))
	inB := makeTarGz(t, files, time.Unix(999_999_999, 0))
	if bytes.Equal(inA, inB) {
		t.Fatal("test inputs must differ (gzip mtimes must differ)")
	}
	ctxA := npmCtx(inA)
	ctxB := npmCtx(inB)
	if err := (Middleware{}).PostFetch(ctxA); err != nil {
		t.Fatal(err)
	}
	if err := (Middleware{}).PostFetch(ctxB); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctxA.Tarball.Bytes, ctxB.Tarball.Bytes) {
		t.Fatal("outputs differ across inputs with different gzip header mtimes")
	}
}

func TestPostFetchNoPackageJSON(t *testing.T) {
	in := makeTarGz(t, map[string]string{"package/README.md": "readme"}, time.Unix(0, 0))
	ctx := npmCtx(in)
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Tarball.Bytes, in) {
		t.Fatal("bytes changed for a tarball without package.json")
	}
}

func TestPostFetchInvalidTarball(t *testing.T) {
	in := []byte("not a gzip")
	ctx := npmCtx(in)
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Tarball.Bytes, in) {
		t.Fatal("bytes changed for an invalid tarball")
	}
}

func TestPostFetchNoInstallScripts(t *testing.T) {
	pkgJSON := `{"name":"testpkg","version":"1.0.0","scripts":{"test":"node test.js","build":"node build.js"}}`
	in := makeTarGz(t, map[string]string{"package/package.json": pkgJSON}, time.Unix(0, 0))
	ctx := npmCtx(in)
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Tarball.Bytes, in) {
		t.Fatal("bytes changed when no install scripts present (should be a no-op)")
	}
}

func TestPostFetchNilTarball(t *testing.T) {
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", "testpkg", "1.0.0", "")
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostFetchNonNpmRegistry(t *testing.T) {
	in := makeTarGz(t, map[string]string{"package/package.json": pkgJSONWithInstallScripts}, time.Unix(0, 0))
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "pypi", "testpkg", "1.0.0", "")
	ctx.Tarball = &pipeline.Tarball{Bytes: in}
	if err := (Middleware{}).PostFetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Tarball.Bytes, in) {
		t.Fatal("bytes changed for a non-npm registry")
	}
}

func TestPreFetchNoOp(t *testing.T) {
	in := makeTarGz(t, map[string]string{"package/package.json": pkgJSONWithInstallScripts}, time.Unix(0, 0))
	ctx := npmCtx(in)
	if err := (Middleware{}).PreFetch(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ctx.Tarball.Bytes, in) {
		t.Fatal("PreFetch must not modify ctx.Tarball")
	}
}
