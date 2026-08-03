package pypi

import (
	"errors"

	"github.com/psenna/dependaproxy/internal/middleware/validation/provenance"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

// provenanceSource resolves PyPI PEP 740 attestations for a project version
// from the simple-API attestations endpoint
// (<base>/<NormalizeName(name)>/<version>/attestations/).
type provenanceSource struct {
	client RegistryClient
}

// NewProvenanceSource returns a provenance.Source that resolves pypi PEP 740
// attestations through client.
func NewProvenanceSource(client RegistryClient) provenance.Source {
	return &provenanceSource{client: client}
}

// Attestations returns the raw sigstore bundle documents for
// ctx.PkgName@ctx.Version.
//
//   - No attestations published (404) -> (nil, nil).
//   - Upstream registry unreachable -> error (routed through on_error).
//
// The PEP 740 document shape is upstream-contract; see
// provenance.ExtractBundles for the defensive parsing used to pull the
// sigstore bundle objects out of the response.
func (s *provenanceSource) Attestations(ctx *pipeline.PipelineContext) ([][]byte, error) {
	raw, err := s.client.FetchAttestations(ctx.Ctx, ctx.PkgName, ctx.Version)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return provenance.ExtractBundles(raw)
}
