// Package provenance implements a validation middleware that verifies the
// package provenance published by the upstream registry:
//
//   - npm: sigstore provenance attestations advertised in the packument
//     `dist.attestations.url` (the SLSA provenance bundle minted by the
//     GitHub Actions publishing workflow).
//   - pypi: PEP 740 attestation bundles served at the simple-API
//     `/<project>/<version>/attestations/` endpoint.
//
// Verification is abstracted behind the Verifier interface so the middleware
// logic (deny/warn, require_provenance, on_error routing) is unit-testable with
// fake bundles. The production verifier is a real sigstore-go verifier wired
// against the public-good trust root (see sigstore.go); if the trust-root /
// network infrastructure is unavailable it degrades to an infrastructure error
// that routes through on_error (fail_open by default -> serve).
package provenance

import (
	"context"
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// name is the config type string the adapters register and config uses.
const name = "provenance-verify"

const (
	modeDeny = "deny"
	modeWarn = "warn"

	onErrorFailOpen   = "fail_open"
	onErrorFailClosed = "fail_closed"

	// defaultTimeout bounds the per-bundle sigstore verification.
	defaultTimeout = 15 * time.Second
)

// Source resolves the provenance attestation bundles for a package version.
type Source interface {
	// Attestations returns the raw sigstore bundle documents (JSON) for the
	// requested package/version, one []byte per published bundle.
	//
	//   - (nil, nil)         — no attestation was published (treated as
	//     "absent", gated by require_provenance).
	//   - (bundles, nil)     — one or more bundles to verify.
	//   - (nil, err)         — verification-infrastructure failure (upstream
	//     registry unreachable, ...), routed through on_error.
	Attestations(ctx *pipeline.PipelineContext) (bundles [][]byte, err error)
}

// Verifier verifies a single sigstore bundle document.
type Verifier interface {
	// Verify verifies a raw bundle.
	//
	//   - (true, nil)   — the bundle is authentic (valid signature, identity,
	//     CT/tlog, ...).
	//   - (false, nil)  — the bundle is invalid/tampered: deny or warn, NOT
	//     on_error.
	//   - (false, err)  — verification infrastructure failed (trust root
	//     unavailable, network outage, ...), routed through on_error.
	Verify(ctx context.Context, bundle []byte) (valid bool, err error)
}

// Params is the decoded `params:` node for the provenance-verify middleware.
type Params struct {
	Mode              string        `yaml:"mode"`               // deny (default) | warn
	RequireProvenance bool          `yaml:"require_provenance"` // deny/warn when no attestation published
	OnError           string        `yaml:"on_error"`           // fail_open (default) | fail_closed
	Identity          string        `yaml:"identity"`           // regex matched against the signing cert SAN (empty = no identity pin, weaker)
	TrustRootDir      string        `yaml:"trust_root_dir"`     // TUF trust-root cache dir (default $HOME/.sigstore/root)
	Timeout           time.Duration `yaml:"timeout"`            // per-verify sigstore timeout (default 15s)
}

// Middleware is the provenance-verify validation middleware.
type Middleware struct {
	src         Source
	verifier    Verifier
	mode        string // deny (default) | warn
	requireProv bool
	onError     string // fail_open (default) | fail_closed
}

// Name returns the config type string.
func (*Middleware) Name() string { return name }

// Validate resolves the package's attestation bundles and verifies them.
//
// Semantics (documented):
//   - No attestation published -> require_provenance ? deny/warn : pass.
//   - At least one bundle verifies -> pass (the FIRST valid bundle wins; npm
//     publishes a single attestation but a registry compromise could append a
//     bogus bundle, so any valid bundle passes).
//   - Every bundle invalid -> deny (default) or warn + metadata annotation.
//   - A Source/Verifier infrastructure error -> on_error (fail_open by default
//     serves; fail_closed rejects).
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	bundles, err := m.src.Attestations(ctx)
	if err != nil {
		return m.applyError(ctx, err)
	}
	if len(bundles) == 0 {
		if m.requireProv {
			return m.applyMissing(ctx)
		}
		return nil
	}
	for _, b := range bundles {
		valid, verr := m.verifier.Verify(ctx.Ctx, b)
		if verr != nil {
			return m.applyError(ctx, verr)
		}
		if valid {
			return nil
		}
	}
	return m.applyInvalid(ctx)
}

// applyInvalid enforces the configured mode on a tampered/invalid attestation.
func (m *Middleware) applyInvalid(ctx *pipeline.PipelineContext) error {
	switch m.mode {
	case modeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("provenance-verify: attestation invalid/tampered (served in warn mode)",
				"package", ctx.PkgName, "version", ctx.Version)
		}
		ctx.Metadata["provenance"] = map[string]any{"status": "invalid"}
		return nil
	default: // deny
		return fmt.Errorf("provenance-verify: %s@%s: attestation invalid/tampered", ctx.PkgName, ctx.Version)
	}
}

// applyMissing enforces require_provenance when no attestation was published.
func (m *Middleware) applyMissing(ctx *pipeline.PipelineContext) error {
	switch m.mode {
	case modeWarn:
		if ctx.Log != nil {
			ctx.Log.Warn("provenance-verify: no provenance attestation published (require_provenance, served in warn mode)",
				"package", ctx.PkgName, "version", ctx.Version)
		}
		ctx.Metadata["provenance"] = map[string]any{"missing": true}
		return nil
	default: // deny
		return fmt.Errorf("provenance-verify: %s@%s: no provenance attestation published", ctx.PkgName, ctx.Version)
	}
}

// applyError handles a verification-infrastructure failure per on_error.
func (m *Middleware) applyError(ctx *pipeline.PipelineContext, err error) error {
	switch m.onError {
	case onErrorFailClosed:
		if ctx.Log != nil {
			ctx.Log.Error("provenance-verify: provenance source unavailable; rejecting (fail_closed)", "err", err)
		}
		return fmt.Errorf("provenance-verify: %w", err)
	default: // fail_open
		if ctx.Log != nil {
			ctx.Log.Warn("provenance-verify: provenance source unavailable; serving (fail_open)", "err", err)
		}
		return nil
	}
}

// New constructs a provenance-verify middleware. A nil verifier installs the
// real sigstore-go verifier (see sigstore.go). Params defaults are applied:
// mode=deny, on_error=fail_open, timeout=15s.
func New(pr Params, src Source, v Verifier) *Middleware {
	if pr.Mode == "" {
		pr.Mode = modeDeny
	}
	if pr.OnError == "" {
		pr.OnError = onErrorFailOpen
	}
	if pr.Timeout == 0 {
		pr.Timeout = defaultTimeout
	}
	if v == nil {
		v = newSigstoreVerifier(pr)
	}
	return &Middleware{
		src:         src,
		verifier:    v,
		mode:        pr.Mode,
		requireProv: pr.RequireProvenance,
		onError:     pr.OnError,
	}
}

// Factory returns a pipeline.ValidationFactory bound to src, registered by the
// npm/pypi adapters under "provenance-verify". The real sigstore verifier is
// installed via New's nil-verifier default.
func Factory(src Source) pipeline.ValidationFactory {
	return func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("%s: decode params: %w", name, err)
			}
		}
		return New(pr, src, nil), nil
	}
}
