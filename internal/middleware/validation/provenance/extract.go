package provenance

import (
	"encoding/json"
	"fmt"
)

// ExtractBundles extracts raw sigstore bundle JSON documents from an upstream
// attestations document. It is deliberately defensive about the exact response
// shapes because the npm and PyPI attestation endpoints differ:
//
//   - npm:  {"attestations":[{"predicateType":..., "bundle":{<bundle>}}]}
//     (the packument `dist.attestations.url` target)
//   - pypi: {"version":1,"attestations":{"<file-digest>":{"attestation_bundles":[
//     {"attestation":{<bundle>}}]}}}  (PEP 740)
//   - bare: {<bundle>}  (a single sigstore bundle document, mediaType-prefixed)
//
// The exact shapes are upstream contracts that can drift; this walker covers
// the common forms and treats any object with a `bundle` or `attestation`
// wrapper key (or a `mediaType` of a bare bundle) as a bundle. One []byte per
// extracted bundle is returned; a document with no recognizable bundle returns
// (nil, nil). A document that is not valid JSON is an error (format failure ->
// on_error routing).
func ExtractBundles(raw []byte) ([][]byte, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("provenance-verify: decode attestations document: %w", err)
	}
	bundles := walkBundles(doc)
	if len(bundles) == 0 {
		return nil, nil
	}
	return bundles, nil
}

// walkBundles recursively collects sigstore bundle objects from a decoded JSON
// value. An object wrapping a `bundle` or `attestation` contributes that
// value; a bare object whose keys look like a bundle document (mediaType
// present) contributes itself; everything else is descended into.
func walkBundles(v any) [][]byte {
	var out [][]byte
	switch t := v.(type) {
	case []any:
		for _, el := range t {
			out = append(out, walkBundles(el)...)
		}
	case map[string]any:
		for _, key := range []string{"bundle", "attestation"} {
			if b, ok := t[key]; ok {
				if m, ok := b.(map[string]any); ok {
					if j, err := json.Marshal(m); err == nil {
						out = append(out, j)
					}
				}
				return out // a wrapper object contributes exactly one bundle
			}
		}
		if _, ok := t["mediaType"]; ok {
			// A bare sigstore bundle document ({"mediaType": ..., ...}).
			if j, err := json.Marshal(t); err == nil {
				out = append(out, j)
			}
			return out
		}
		for _, val := range t {
			out = append(out, walkBundles(val)...)
		}
	}
	return out
}
