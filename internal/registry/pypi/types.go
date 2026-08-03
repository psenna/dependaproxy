// Package pypi is the PyPI registry adapter: data model (PEP 691 Simple JSON
// API + PEP 503 HTML), upstream client, per-file validated storage, middleware,
// and routes. It implements adapter.Adapter and is mounted at its configured
// prefix (e.g. /pypi).
package pypi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned when a project or file does not exist upstream.
var ErrNotFound = errors.New("pypi: not found")

// RegistryClient fetches PyPI simple-API metadata and artifacts from upstream.
type RegistryClient interface {
	// FetchIndex returns the trimmed project model (PEP 691 JSON).
	FetchIndex(ctx context.Context, name string) (*Project, error)
	// FetchIndexRaw returns the upstream index body verbatim + its content-type,
	// for the index route to serve (with file URLs rewritten). accept is the
	// content-type to request (PEP 691 JSON or HTML).
	FetchIndexRaw(ctx context.Context, name, accept string) ([]byte, string, error)
	// FetchFile streams the artifact at fileURL. contentLength is -1 if unknown.
	FetchFile(ctx context.Context, fileURL string) (io.ReadCloser, int64, error)
	// FetchAttestations fetches the PEP 740 attestation document for a project
	// version (GET <base>/<name>/<version>/attestations/). 404 maps to
	// ErrNotFound (no attestations published).
	FetchAttestations(ctx context.Context, name, version string) ([]byte, error)
}

// Project is the trimmed PEP 691 simple-index model for one project.
type Project struct {
	Name  string `json:"name"`
	Files []File `json:"files"`
}

// File is one release artifact (wheel or sdist). Version is parsed from
// Filename (PEP 427/625) via internal/pypifilename — it is not a PEP 691 field.
type File struct {
	Filename       string            `json:"filename"`
	URL            string            `json:"url"`
	Hashes         map[string]string `json:"hashes"` // {"sha256": "...", ...}
	RequiresPython string            `json:"requires-python,omitempty"`
	Yanked         Yanked            `json:"yanked,omitempty"`      // bool | string (PEP 592)
	UploadTime     time.Time         `json:"upload-time,omitempty"` // PEP 700, OPTIONAL -> fail-closed
	Size           int64             `json:"size,omitempty"`
}

// Yanked models PEP 592: a bool, or a non-empty string (the reason).
type Yanked struct {
	raw json.RawMessage
	set bool
}

// UnmarshalJSON stores the raw value for later interpretation.
func (y *Yanked) UnmarshalJSON(b []byte) error { y.raw = b; y.set = true; return nil }

// Bool reports whether the file is yanked (true, or a non-empty reason string).
func (y Yanked) Bool() bool {
	if !y.set {
		return false
	}
	var b bool
	if json.Unmarshal(y.raw, &b) == nil {
		return b
	}
	return len(y.raw) > 0 && string(y.raw) != `""`
}
