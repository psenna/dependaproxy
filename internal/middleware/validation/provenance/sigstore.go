package provenance

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// errInfrastructure is returned by the real sigstore verifier when the
// verification infrastructure itself is unavailable (TUF trust-root bootstrap
// failure, network, ...). The middleware routes it through on_error (fail_open
// by default -> serve). It is distinct from a tamper signal, which is
// (false, nil).
var errInfrastructure = errors.New("provenance-verify: sigstore verification infrastructure unavailable")

// sigstoreVerifier is the real sigstore-go verifier, wired against the
// sigstore public-good trust root (Fulcio certificates + Rekor CT/tlog),
// resolved through sigstore-go's TUF client.
//
// The TUF trust-root bootstrap performs network I/O on first use, so it is
// deferred to the first Verify call and attempted once (then cached): a missing
// trust root or blocked network degrades to errInfrastructure (fail_open by
// default) instead of failing middleware construction at config build time.
type sigstoreVerifier struct {
	identity  string // regex matched against the signing cert SAN; "" = no identity pin
	timeout   time.Duration
	cachePath string // TUF trust-root cache dir; "" = sigstore default ($HOME/.sigstore/root)

	mu   sync.Mutex
	done bool
	ok   bool
	sev  *verify.Verifier
	err  error
}

// NewSigstoreVerifier builds the real sigstore-go verifier from pr.
//
// Exported so adapters can build one Verifier from the OPERATOR's static
// top-level configuration and pin it into the "provenance-verify" factory
// (provenance.FactoryWithVerifier(src, sharedVerifier) instead of
// provenance.Factory(src)) — see the security-review H4 fix: the nil-verifier
// path in New rebuilds a fresh sigstoreVerifier from whatever Params it's
// called with, so a caller able to submit arbitrary params (the admin API's
// per-project middleware overrides) can redirect TrustRootDir to any
// filesystem path. A pinned Verifier is immune to that: New ignores
// pr.Identity/pr.TrustRootDir/pr.Timeout entirely once a non-nil Verifier is
// supplied, so only pr.Mode/pr.RequireProvenance/pr.OnError can still vary
// per-project.
func NewSigstoreVerifier(pr Params) Verifier {
	if pr.Timeout == 0 {
		pr.Timeout = defaultTimeout
	}
	return &sigstoreVerifier{
		identity:  pr.Identity,
		timeout:   pr.Timeout,
		cachePath: pr.TrustRootDir,
	}
}

// Verify verifies a raw sigstore bundle document (protobuf-JSON) against the
// public-good trust root AND binds it to artifactSha256Hex (H3): the bundle's
// DSSE envelope must carry an in-toto subject digest equal to the artifact
// actually being served, not merely be an otherwise-valid signature over some
// document. Returns:
//
//	(true, nil)   authentic provenance for this exact artifact
//	(false, nil)  bundle invalid/tampered (bad signature, unknown/expired
//	              signing certificate, SAN mismatch, missing CT/tlog,
//	              malformed bundle JSON) OR authentic but for a different
//	              artifact (subject digest mismatch)
//	(false, err)  verification infrastructure failed (trust root unavailable)
func (s *sigstoreVerifier) Verify(ctx context.Context, raw []byte, artifactSha256Hex string) (bool, error) {
	sev, err := s.engine(ctx)
	if err != nil {
		return false, err
	}

	digest, err := hex.DecodeString(artifactSha256Hex)
	if err != nil {
		// The digest is computed internally by hash.Sha256Hex and passed
		// through PipelineContext.Metadata, never client-controlled, so a
		// malformed hex string here is a programming error, not a tamper
		// signal from an attacker-controlled input.
		return false, fmt.Errorf("%w: malformed artifact digest: %v", errInfrastructure, err)
	}

	var b bundle.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		// A bundle document that is not valid sigstore bundle JSON is a tamper
		// signal, not an infrastructure failure.
		return false, nil
	}

	policyOpts := []verify.PolicyOption{}
	if s.identity != "" {
		// Pin the signing certificate SAN against the configured regex
		// (exact values are valid regexes). The OIDC issuer is not pinned in
		// v1 — the SAN is the actionable identity for provenance.
		certID, err := verify.NewShortCertificateIdentity("", "", "", s.identity)
		if err != nil {
			return false, errInfrastructure
		}
		policyOpts = append(policyOpts, verify.WithCertificateIdentity(certID))
	} else {
		// No identity pin: the signature and CT/tlog inclusion are still
		// verified against the public-good trust root, but the signing identity
		// is not matched. Weaker — recommend setting `identity` in production.
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
	}

	// WithArtifactDigest asserts the DSSE envelope's in-toto statement subject
	// digest equals artifactSha256Hex — this is what closes H3: a bundle whose
	// subject is a different file (or a different version) fails here even
	// though its signature is otherwise perfectly valid.
	if _, err := sev.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), policyOpts...)); err != nil {
		// Any verification failure (bad signature, expired cert, missing
		// CT/tlog, OR a digest mismatch) means the bundle does not authenticate
		// this artifact -> tamper signal.
		return false, nil
	}
	return true, nil
}

// engine returns the initialized sigstore-go Verifier, bootstrapping the TUF
// trust root on first use. The result is cached; a failed bootstrap is not
// retried within the process lifetime.
func (s *sigstoreVerifier) engine(ctx context.Context) (*verify.Verifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.done {
		s.sev, s.err = s.build()
		s.ok = s.err == nil
		s.done = true
	}
	if !s.ok {
		return nil, s.err
	}
	return s.sev, nil
}

// build bootstraps the live TUF trust root and constructs the sigstore-go
// verifier. It is called once per middleware instance (lazily, on first use).
func (s *sigstoreVerifier) build() (*verify.Verifier, error) {
	opts := tuf.DefaultOptions()
	if s.cachePath != "" {
		opts.CachePath = s.cachePath
	}
	// Bound the TUF bootstrap HTTP calls with the configured timeout (the
	// sigstore-go verifier's own tlog/CT HTTP uses library defaults).
	fetcher := fetcher.NewDefaultFetcher()
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())
	fetcher.SetHTTPClient(&http.Client{Timeout: s.timeout})
	opts.Fetcher = fetcher

	// Live TUF resolution of the public-good trusted_root.json (Fulcio
	// certificate authorities + Rekor transparency logs). Cached under
	// CachePath across restarts; requires network on first run.
	ltr, err := root.NewLiveTrustedRoot(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: TUF trust root bootstrap: %v", errInfrastructure, err)
	}

	sev, err := verify.NewVerifier(ltr,
		verify.WithTransparencyLog(1),             // Rekor artifact-transparency inclusion
		verify.WithSignedCertificateTimestamps(1), // Fulcio certificate transparency
		verify.WithObserverTimestamps(1),          // either RFC3161 or integrated timestamp
	)
	if err != nil {
		return nil, fmt.Errorf("%w: build verifier: %v", errInfrastructure, err)
	}
	return sev, nil
}
