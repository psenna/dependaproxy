package npm

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

func TestNpmServeUntrustedHonorsPostFetchBytes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("UPSTREAM"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("UPSTREAM")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{sentinelMutation{}}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, client, store, global)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "MUTATED" {
		t.Fatalf("code=%d body=%q want 200/MUTATED", code, body)
	}
	want, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("UPSTREAM")))
	if got := store.recs[k("testpkg", "1.0.0")].ValidationHash; got != want {
		t.Errorf("stored ValidationHash = %q, want sha256(UPSTREAM)=%q", got, want)
	}
}

func TestNpmServeTrustedHonorsPostFetchBytes(t *testing.T) {
	dir := t.TempDir()
	store := newMemStore()
	goodHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("UPSTREAM")))
	store.recs[k("testpkg", "1.0.0")] = Record{Name: "testpkg", Version: "1.0.0", ValidationHash: goodHash, ValidatedAt: time.Now().UTC()}
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("UPSTREAM"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("UPSTREAM")}
	global := &project.Resolved{Mutation: pipeline.MutationPipeline{Chain: []pipeline.MutationMiddleware{sentinelMutation{}}}}
	a := newTestAdapterWithGlobal(t, "/npm", dir, 0, client, store, global)
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 200 || string(body) != "MUTATED" {
		t.Fatalf("code=%d body=%q want 200/MUTATED (trusted path re-applies the mutation)", code, body)
	}
	// Trust-anchor invariant: the stored hash is of the UPSTREAM bytes, while
	// the served body is the mutated bytes. The trusted path must not overwrite
	// the stored hash.
	if got := store.recs[k("testpkg", "1.0.0")].ValidationHash; got != goodHash {
		t.Errorf("stored ValidationHash = %q, want sha256(UPSTREAM)=%q (trusted path must not rehash mutated bytes)", got, goodHash)
	}
}
