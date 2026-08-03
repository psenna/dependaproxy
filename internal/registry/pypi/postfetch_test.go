package pypi

import (
	"bytes"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// sentinelMutation rewrites ctx.Tarball.Bytes in PostFetch. It proves the
// adapter honors a PostFetch byte rewrite on the serve path (the adapter-fix
// guard `if ctx.Tarball != nil && ctx.Tarball.Bytes != nil { body = ... }`).
type sentinelMutation struct{}

func (sentinelMutation) Name() string { return "sentinel" }
func (sentinelMutation) PreFetch(*pipeline.PipelineContext) error {
	return nil
}
func (sentinelMutation) PostFetch(ctx *pipeline.PipelineContext) error {
	ctx.Tarball.Bytes = []byte("MUTATED")
	return nil
}

func TestPypiServeUntrustedHonorsPostFetchBytes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("UPSTREAM"))
	c := &rawClient{project: proj, raw: raw, file: []byte("UPSTREAM")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{sentinelMutation{}}}}
	a := newTestAdapterWithGlobal(t, "/pypi", dir, 0, c, store, global)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "MUTATED" {
		t.Fatalf("code=%d body=%q want 200/MUTATED", code, body)
	}
	want, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("UPSTREAM")))
	if got := store.recs[pkey("testpkg", "1.0.0", wheelFile)].Sha256; got != want {
		t.Errorf("stored Sha256 = %q, want sha256(UPSTREAM)=%q", got, want)
	}
}

func TestPypiServeTrustedHonorsPostFetchBytes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("UPSTREAM")))
	store.recs[pkey("testpkg", "1.0.0", wheelFile)] = Record{Name: "testpkg", Version: "1.0.0", Filename: wheelFile, Sha256: goodHash, ValidatedAt: time.Now().UTC()}
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("UPSTREAM"))
	c := &rawClient{project: proj, raw: raw, file: []byte("UPSTREAM")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{sentinelMutation{}}}}
	a := newTestAdapterWithGlobal(t, "/pypi", dir, 0, c, store, global)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != 200 || string(body) != "MUTATED" {
		t.Fatalf("code=%d body=%q want 200/MUTATED (trusted path re-applies the mutation)", code, body)
	}
	// Trust-anchor invariant: the stored hash is of the UPSTREAM bytes, while
	// the served body is the mutated bytes. The trusted path must not overwrite
	// the stored hash.
	if got := store.recs[pkey("testpkg", "1.0.0", wheelFile)].Sha256; got != goodHash {
		t.Errorf("stored Sha256 = %q, want sha256(UPSTREAM)=%q (trusted path must not rehash mutated bytes)", got, goodHash)
	}
}
