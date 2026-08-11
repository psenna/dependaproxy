package denylist

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// fakeStore is an in-memory Store for unit tests. It records every Lookup's
// arguments so tests can assert scoping and whether the store was consulted.
type fakeStore struct {
	mu      sync.Mutex
	reason  string
	ok      bool
	err     error
	calls   int
	gotReg  string
	gotName string
	gotVer  string
	gotSha  string
	gotKey  string
}

func (f *fakeStore) Lookup(_ context.Context, registry, name, version, sha256, projectKey string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.gotReg = registry
	f.gotName = name
	f.gotVer = version
	f.gotSha = sha256
	f.gotKey = projectKey
	return f.reason, f.ok, f.err
}

func (f *fakeStore) Record(context.Context, Denial) error { return nil }

// fakeValidation counts Validate calls; used to assert the deny-list-check
// middleware short-circuits the downstream chain.
type fakeValidation struct {
	calls int
}

func (f *fakeValidation) Name() string { return "fake-validation" }
func (f *fakeValidation) Validate(*pipeline.PipelineContext) error {
	f.calls++
	return nil
}

func testCtx() *pipeline.PipelineContext {
	pc := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", "pkg", "1.0.0", "")
	pc.Tarball = &pipeline.Tarball{Bytes: []byte("artifact-bytes")}
	return pc
}

func build(t *testing.T, st Store, n yaml.Node) pipeline.ValidationMiddleware {
	t.Helper()
	mw, err := Factory(st)(n)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return mw
}

func TestValidateDenied(t *testing.T) {
	st := &fakeStore{reason: "blocked by policy", ok: true}
	mw := build(t, st, yaml.Node{})
	err := mw.Validate(testCtx())
	if err == nil {
		t.Fatal("Validate = nil, want denial error")
	}
	if !strings.HasPrefix(err.Error(), "deny-list-check:") {
		t.Errorf("err = %q, want prefix %q", err, "deny-list-check:")
	}
	if !strings.Contains(err.Error(), "pkg@1.0.0") {
		t.Errorf("err = %q, want pkg@1.0.0", err)
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("err = %q, want stored reason", err)
	}
	if st.calls != 1 {
		t.Errorf("store consulted %d times, want 1", st.calls)
	}
}

func TestValidateNotDenied(t *testing.T) {
	st := &fakeStore{ok: false}
	mw := build(t, st, yaml.Node{})
	if err := mw.Validate(testCtx()); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if st.calls != 1 {
		t.Errorf("store consulted %d times, want 1", st.calls)
	}
}

func TestValidateStoreErrorFailOpen(t *testing.T) {
	st := &fakeStore{err: errors.New("postgres down")}
	mw := build(t, st, yaml.Node{})
	if err := mw.Validate(testCtx()); err != nil {
		t.Fatalf("Validate = %v, want nil (fail-open)", err)
	}
	if st.calls != 1 {
		t.Errorf("store consulted %d times, want 1", st.calls)
	}
}

func TestValidateNilTarballSkipsStore(t *testing.T) {
	st := &fakeStore{reason: "blocked", ok: true}
	mw := build(t, st, yaml.Node{})
	ctx := testCtx()
	ctx.Tarball = nil
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if st.calls != 0 {
		t.Errorf("store consulted %d times, want 0", st.calls)
	}
}

func TestValidateEmptyTarballSkipsStore(t *testing.T) {
	st := &fakeStore{reason: "blocked", ok: true}
	mw := build(t, st, yaml.Node{})
	ctx := testCtx()
	ctx.Tarball = &pipeline.Tarball{Bytes: nil}
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if st.calls != 0 {
		t.Errorf("store consulted %d times, want 0", st.calls)
	}
}

func TestValidatePassesProjectKeyAndHash(t *testing.T) {
	st := &fakeStore{ok: false}
	mw := build(t, st, yaml.Node{})
	ctx := testCtx()
	ctx.ProjectKey = "proj-a"
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if st.gotKey != "proj-a" {
		t.Errorf("lookup projectKey = %q, want %q", st.gotKey, "proj-a")
	}
	if st.gotReg != "npm" || st.gotName != "pkg" || st.gotVer != "1.0.0" {
		t.Errorf("lookup args = (%q, %q, %q), want (npm, pkg, 1.0.0)", st.gotReg, st.gotName, st.gotVer)
	}
	wantHash, _, err := hash.Sha256Hex(bytes.NewReader([]byte("artifact-bytes")))
	if err != nil {
		t.Fatal(err)
	}
	if st.gotSha != wantHash {
		t.Errorf("lookup sha256 = %q, want %q", st.gotSha, wantHash)
	}
}

func TestValidateUsesMetadataSha256(t *testing.T) {
	st := &fakeStore{ok: false}
	mw := build(t, st, yaml.Node{})
	ctx := testCtx()
	preset := strings.Repeat("ab", 32) // 64-hex string, != sha256("artifact-bytes")
	ctx.Metadata["sha256"] = preset
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	if st.gotSha != preset {
		t.Errorf("lookup sha256 = %q, want preset %q (must read the stash, not recompute)", st.gotSha, preset)
	}
}

func TestValidateFallbackHashesWhenMetadataAbsent(t *testing.T) {
	st := &fakeStore{ok: false}
	mw := build(t, st, yaml.Node{})
	ctx := testCtx() // no "sha256" metadata preset
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	want, _, err := hash.Sha256Hex(bytes.NewReader(ctx.Tarball.Bytes))
	if err != nil {
		t.Fatal(err)
	}
	if st.gotSha != want {
		t.Errorf("lookup sha256 = %q, want %q", st.gotSha, want)
	}
}

func TestValidateDisabled(t *testing.T) {
	st := &fakeStore{reason: "blocked", ok: true}
	mw := build(t, st, paramsNode(t, "enabled: false"))
	if err := mw.Validate(testCtx()); err != nil {
		t.Fatalf("Validate = %v, want nil (disabled)", err)
	}
	if st.calls != 0 {
		t.Errorf("store consulted %d times, want 0", st.calls)
	}
}

func TestValidateNilStore(t *testing.T) {
	mw := build(t, nil, yaml.Node{})
	if err := mw.Validate(testCtx()); err != nil {
		t.Fatalf("Validate = %v, want nil (nil store)", err)
	}
}

func TestFactoryDefaultEnabled(t *testing.T) {
	st := &fakeStore{reason: "blocked", ok: true}
	mw := build(t, st, yaml.Node{})
	if err := mw.Validate(testCtx()); err == nil {
		t.Fatal("Validate = nil, want denial error (enabled defaults true when listed)")
	}
}

func TestFactoryDecodeError(t *testing.T) {
	var n yaml.Node
	if err := n.Encode(map[string]any{"enabled": "not-a-bool"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Factory(&fakeStore{})(n); err == nil {
		t.Fatal("factory should reject a non-bool enabled param")
	}
}

func TestChainShortCircuitSkipsGuarddog(t *testing.T) {
	st := &fakeStore{reason: "blocked by policy", ok: true}
	guarddog := &fakeValidation{}

	reg := pipeline.NewRegistry()
	reg.RegisterValidation("deny-list-check", Factory(st))
	reg.RegisterValidation("guarddog-scan", func(yaml.Node) (pipeline.ValidationMiddleware, error) {
		return guarddog, nil
	})

	chain, err := reg.BuildValidation([]config.Middleware{
		{Type: "deny-list-check", Params: yaml.Node{}},
		{Type: "guarddog-scan", Params: yaml.Node{}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	err = chain.Run(testCtx())
	if err == nil {
		t.Fatal("Run = nil, want denial error")
	}
	if !strings.Contains(err.Error(), "blocked by policy") {
		t.Errorf("err = %q, want stored reason", err)
	}
	if guarddog.calls != 0 {
		t.Errorf("guarddog Validate called %d times, want 0 (short-circuited)", guarddog.calls)
	}
}

func paramsNode(t *testing.T, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatalf("yaml params: %v", err)
	}
	return n
}
