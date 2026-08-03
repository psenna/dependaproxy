// Package npm is the npm registry adapter: data model, upstream client,
// validated-package storage, middleware, and routes. It implements the
// adapter.Adapter contract and is mounted at its configured prefix (e.g. /npm).
package npm

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned when a package or version does not exist upstream.
var ErrNotFound = errors.New("npm: not found")

// RegistryClient fetches npm registry metadata and tarballs from upstream.
type RegistryClient interface {
	FetchPackument(ctx context.Context, name string) (*Packument, error)
	FetchPackumentRaw(ctx context.Context, name string) ([]byte, error)
	FetchTarball(ctx context.Context, tarballURL string) (io.ReadCloser, int64, error)
	// FetchBytes GETs an arbitrary URL (e.g. a dist.attestations.url provenance
	// bundle) and returns the body verbatim. 404 maps to ErrNotFound.
	FetchBytes(ctx context.Context, url string) ([]byte, error)
}

// Packument is the npm registry package metadata document (trimmed to the
// fields the proxy needs).
type Packument struct {
	Name     string               `json:"name"`
	Versions map[string]Version   `json:"versions"`
	Time     map[string]time.Time `json:"time"`
	DistTags map[string]string    `json:"dist-tags"`
}

// Version is one published version within a packument.
type Version struct {
	Version string `json:"version"`
	Dist    Dist   `json:"dist"`
}

// Dist is the download location + upstream integrity for a version.
type Dist struct {
	Tarball      string        `json:"tarball"`
	Integrity    string        `json:"integrity"`
	Attestations *Attestations `json:"attestations,omitempty"`
}

// Attestations is the npm packument dist.attestations object: a URL from which
// the sigstore provenance bundle(s) for the version can be fetched (the inline
// `provenance` field is not modeled — the URL is the fetch path we use).
type Attestations struct {
	URL             string `json:"url"`
	ProxiedSigstore string `json:"proxiedSigstoreUrl,omitempty"`
}
