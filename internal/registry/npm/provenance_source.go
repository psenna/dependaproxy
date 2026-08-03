package npm

import (
	"encoding/json"
	"errors"

	"github.com/psenna/dependaproxy/internal/middleware/validation/provenance"
	"github.com/psenna/dependaproxy/internal/pipeline"
)

// provenanceSource resolves npm sigstore provenance attestations for a package
// version. npm publishes the attestation bundle URL in the packument at
// versions[<version>].dist.attestations.url; the target document is a JSON
// wrapper holding one or more sigstore bundles.
type provenanceSource struct {
	client RegistryClient
}

// NewProvenanceSource returns a provenance.Source that resolves npm
// attestations through client.
func NewProvenanceSource(client RegistryClient) provenance.Source {
	return &provenanceSource{client: client}
}

// Attestations returns the raw sigstore bundle documents for
// ctx.PkgName@ctx.Version.
//
//   - No attestations published -> (nil, nil).
//   - Upstream registry unreachable (packument fetch fails) -> error (routed
//     through on_error).
func (s *provenanceSource) Attestations(ctx *pipeline.PipelineContext) ([][]byte, error) {
	att := s.attestationsFromIndex(ctx)
	if att == nil || att.URL == "" {
		// ctx.Index may be nil/missing when the retrieval chain short-circuited
		// (e.g. a cache hit never reached the upstream-registry middleware that
		// populates ctx.Index). Fall back to a raw packument fetch to locate
		// dist.attestations.url.
		raw, err := s.client.FetchPackumentRaw(ctx.Ctx, ctx.PkgName)
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var doc struct {
			Versions map[string]struct {
				Dist struct {
					Attestations *Attestations `json:"attestations"`
				} `json:"dist"`
			} `json:"versions"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if v, ok := doc.Versions[ctx.Version]; ok {
			att = v.Dist.Attestations
		}
	}
	if att == nil || att.URL == "" {
		return nil, nil
	}

	raw, err := s.client.FetchBytes(ctx.Ctx, att.URL)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return provenance.ExtractBundles(raw)
}

// attestationsFromIndex locates dist.attestations from the already-fetched
// packument carried on ctx.Index (set by the upstream-registry retrieval
// middleware), avoiding a second packument fetch on the validation path.
func (s *provenanceSource) attestationsFromIndex(ctx *pipeline.PipelineContext) *Attestations {
	pack, ok := ctx.Index.(*Packument)
	if !ok || pack == nil {
		return nil
	}
	v, ok := pack.Versions[ctx.Version]
	if !ok {
		return nil
	}
	return v.Dist.Attestations
}
