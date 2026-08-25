package provenance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// fakeSource serves canned attestation bundles or a canned error.
type fakeSource struct {
	bundles [][]byte
	err     error
}

func (f *fakeSource) Attestations(_ *pipeline.PipelineContext) ([][]byte, error) {
	return f.bundles, f.err
}

// fakeVerifier decides by bundle content:
//
//	[]byte("VALID")    -> (true, nil)
//	[]byte("TAMPERED") -> (false, nil)
//	[]byte("INFRA")    -> (false, errInfrastructure)
//
// It also records the last artifactSha256Hex it was called with, so tests can
// assert the digest reaching the verifier (H3).
type fakeVerifier struct {
	mu     sync.Mutex
	digest string
}

func (f *fakeVerifier) Verify(_ context.Context, b []byte, artifactSha256Hex string) (bool, error) {
	f.mu.Lock()
	f.digest = artifactSha256Hex
	f.mu.Unlock()
	switch string(b) {
	case "VALID":
		return true, nil
	case "TAMPERED":
		return false, nil
	case "INFRA":
		return false, errInfrastructure
	default:
		return false, nil
	}
}

func (f *fakeVerifier) lastDigest() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.digest
}

// testDigest is the artifact sha256 hex stashed on the context by newCtx,
// standing in for what an adapter's serveUntrusted would have set before
// running the validation chain.
const testDigest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

func newCtx() *pipeline.PipelineContext {
	ctx := pipeline.NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0", "")
	ctx.Metadata["sha256"] = testDigest
	return ctx
}

func buildMw(pr Params, src Source) *Middleware {
	return New(pr, src, &fakeVerifier{})
}

func TestValidateValidBundlePasses(t *testing.T) {
	mw := buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("VALID")}})
	if err := mw.Validate(newCtx()); err != nil {
		t.Fatalf("valid bundle should pass, got %v", err)
	}
}

func TestValidateTamperedDeny(t *testing.T) {
	mw := buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("TAMPERED")}})
	err := mw.Validate(newCtx())
	if err == nil {
		t.Fatal("tampered bundle in deny mode should error")
	}
	if !strings.Contains(err.Error(), "pkg@1.0.0") {
		t.Fatalf("deny error should name package@version, got %q", err)
	}
}

func TestValidateTamperedWarn(t *testing.T) {
	ctx := newCtx()
	mw := buildMw(Params{Mode: modeWarn}, &fakeSource{bundles: [][]byte{[]byte("TAMPERED")}})
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("tampered bundle in warn mode should serve, got %v", err)
	}
	annotate := ctx.Metadata["provenance"]
	if annotate == nil {
		t.Fatal("warn mode should annotate ctx.Metadata[\"provenance\"]")
	}
	if m, ok := annotate.(map[string]any); !ok || m["status"] != "invalid" {
		t.Fatalf("provenance metadata = %#v, want {\"status\":\"invalid\"}", annotate)
	}
}

func TestValidateAbsentNotRequiredPasses(t *testing.T) {
	mw := buildMw(Params{}, &fakeSource{}) // no bundles, no error
	if err := mw.Validate(newCtx()); err != nil {
		t.Fatalf("absent attestation without require_provenance should pass, got %v", err)
	}
}

func TestValidateAbsentRequiredDeny(t *testing.T) {
	mw := buildMw(Params{RequireProvenance: true}, &fakeSource{})
	if err := mw.Validate(newCtx()); err == nil {
		t.Fatal("absent attestation with require_provenance should deny")
	}
}

func TestValidateAbsentRequiredWarn(t *testing.T) {
	ctx := newCtx()
	mw := buildMw(Params{Mode: modeWarn, RequireProvenance: true}, &fakeSource{})
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("absent attestation in warn mode should serve, got %v", err)
	}
	annotate := ctx.Metadata["provenance"]
	if m, ok := annotate.(map[string]any); !ok || m["missing"] != true {
		t.Fatalf("provenance metadata = %#v, want {\"missing\":true}", annotate)
	}
}

func TestValidateInfraErrFailOpenServes(t *testing.T) {
	ctx := newCtx()
	mw := buildMw(Params{}, &fakeSource{err: errors.New("upstream down")})
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("source failure in fail_open mode should serve, got %v", err)
	}
}

func TestValidateInfraErrFailClosedRejects(t *testing.T) {
	mw := buildMw(Params{OnError: onErrorFailClosed}, &fakeSource{err: errors.New("upstream down")})
	if err := mw.Validate(newCtx()); err == nil {
		t.Fatal("source failure in fail_closed mode should reject")
	}
}

func TestValidateVerifierInfraErrRoutesThroughOnError(t *testing.T) {
	ctx := newCtx()
	// One INFRA bundle: the verifier reports an infrastructure failure, which
	// must route through on_error (fail_open default -> serve).
	mw := buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("INFRA")}})
	if err := mw.Validate(ctx); err != nil {
		t.Fatalf("verifier infra failure in fail_open mode should serve, got %v", err)
	}

	// fail_closed variant rejects.
	mw = buildMw(Params{OnError: onErrorFailClosed}, &fakeSource{bundles: [][]byte{[]byte("INFRA")}})
	if err := mw.Validate(newCtx()); err == nil {
		t.Fatal("verifier infra failure in fail_closed mode should reject")
	}
}

func TestValidateFirstValidBundleWins(t *testing.T) {
	// An attacker appends a tampered bundle after the valid one; the first valid
	// bundle passes (npm publishes a single attestation).
	mw := buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("VALID"), []byte("TAMPERED")}})
	if err := mw.Validate(newCtx()); err != nil {
		t.Fatalf("any valid bundle should pass, got %v", err)
	}
	// All invalid -> deny even when one bundle is "VALID-later" only.
	mw = buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("TAMPERED"), []byte("TAMPERED")}})
	if err := mw.Validate(newCtx()); err == nil {
		t.Fatal("all-invalid bundles should deny")
	}
}

// TestValidatePassesArtifactDigestToVerifier is the regression test for H3:
// the digest Validate hands to the verifier must be the one stashed on the
// context (the actual served artifact's sha256), not derived from the bundle
// content or omitted.
func TestValidatePassesArtifactDigestToVerifier(t *testing.T) {
	v := &fakeVerifier{}
	mw := New(Params{}, &fakeSource{bundles: [][]byte{[]byte("VALID")}}, v)
	if err := mw.Validate(newCtx()); err != nil {
		t.Fatalf("valid bundle should pass, got %v", err)
	}
	if got := v.lastDigest(); got != testDigest {
		t.Errorf("verifier received digest %q, want %q", got, testDigest)
	}
}

// TestValidateMissingDigestRoutesThroughOnError is the regression test for
// the defensive half of H3: Validate must not call the verifier at all (and
// so cannot accidentally verify without binding to an artifact) when no
// digest is available on the context -- it treats that as an infrastructure
// error, routed through on_error like any other.
func TestValidateMissingDigestRoutesThroughOnError(t *testing.T) {
	ctxNoDigest := pipeline.NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0", "")
	// deliberately do not set ctx.Metadata["sha256"]

	mw := buildMw(Params{}, &fakeSource{bundles: [][]byte{[]byte("VALID")}})
	if err := mw.Validate(ctxNoDigest); err != nil {
		t.Fatalf("missing digest in fail_open mode should serve, got %v", err)
	}

	mw = New(Params{OnError: onErrorFailClosed}, &fakeSource{bundles: [][]byte{[]byte("VALID")}}, &fakeVerifier{})
	if err := mw.Validate(pipeline.NewPipelineContext(context.Background(), nil, "npm", "pkg", "1.0.0", "")); err == nil {
		t.Fatal("missing digest in fail_closed mode should reject")
	}
}

func yamlNode(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	return n
}

func TestFactoryDecodesParams(t *testing.T) {
	src := &fakeSource{}
	f := Factory(src)
	mw, err := f(yamlNode("mode: warn\nrequire_provenance: true\non_error: fail_closed\nidentity: \"^https://github.com/example/\"\ntimeout: 5s"))
	if err != nil {
		t.Fatalf("Factory decode: %v", err)
	}
	m, ok := mw.(*Middleware)
	if !ok {
		t.Fatalf("Factory returned %T, want *Middleware", mw)
	}
	if m.mode != modeWarn {
		t.Errorf("mode = %q, want %q", m.mode, modeWarn)
	}
	if !m.requireProv {
		t.Error("require_provenance should be true")
	}
	if m.onError != onErrorFailClosed {
		t.Errorf("on_error = %q, want %q", m.onError, onErrorFailClosed)
	}
	// The nil-verifier default installs the real sigstore verifier (lazy; no
	// network at construction).
	sv, ok := m.verifier.(*sigstoreVerifier)
	if !ok {
		t.Fatalf("verifier = %T, want *sigstoreVerifier", m.verifier)
	}
	if sv.identity != "^https://github.com/example/" {
		t.Errorf("identity = %q", sv.identity)
	}

	// Zero node -> defaults.
	mw2, err := f(yaml.Node{})
	if err != nil {
		t.Fatalf("Factory zero params: %v", err)
	}
	m2 := mw2.(*Middleware)
	if m2.mode != modeDeny || m2.onError != onErrorFailOpen {
		t.Errorf("defaults: mode=%q on_error=%q, want deny/fail_open", m2.mode, m2.onError)
	}
}

func TestName(t *testing.T) {
	mw := buildMw(Params{}, &fakeSource{})
	if mw.Name() != "provenance-verify" {
		t.Errorf("Name() = %q, want provenance-verify", mw.Name())
	}
}
