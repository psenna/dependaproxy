// Package registry holds the registry data model and (in a later task) the
// registry client. Only the npm packument types live here for now; the HTTP
// client is added when the npm registry support lands.
package registry

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned when a package or version does not exist upstream.
var ErrNotFound = errors.New("registry: not found")

// RegistryClient fetches package metadata and artifacts from an upstream
// registry. Implementations must honor ctx for cancellation/timeout.
type RegistryClient interface {
	// FetchPackument returns the package metadata document, or ErrNotFound.
	FetchPackument(ctx context.Context, name string) (*Packument, error)
	// FetchTarball streams the package tarball; the caller must close the
	// ReadCloser. contentLength is -1 if unknown.
	FetchTarball(ctx context.Context, tarballURL string) (io.ReadCloser, int64, error)
}

// Packument is the npm registry package metadata document.
type Packument struct {
	Name     string               `json:"name"`
	Versions map[string]Version   `json:"versions"`
	Time     map[string]time.Time `json:"time"` // version -> publish time; "created"/"modified" also present
	DistTags map[string]string    `json:"dist-tags"`
}

// Version is one published version within a packument.
type Version struct {
	Version string `json:"version"`
	Dist    Dist   `json:"dist"`
}

// Dist is the download location + upstream integrity for a version. Integrity
// is the upstream sha512; DependaProxy uses its own sha256 as the trust anchor,
// so Integrity is only a defense-in-depth sanity check.
type Dist struct {
	Tarball   string `json:"tarball"`
	Integrity string `json:"integrity"`
}
