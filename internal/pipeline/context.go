// Package pipeline is DependaProxy's orchestration core: it defines the
// validation/retrieval/mutation middleware contracts, the registry that maps
// config `type:` strings to middleware factories, and the runners that drive
// the chains. It is registry-agnostic: per-registry data is carried as `any`
// (Index/Artifact) and concrete middleware type-assert. This keeps a single
// shared engine across all registry adapters (npm, pypi, maven, ...).
package pipeline

import (
	"context"
	"log/slog"
)

// Tarball is the package artifact carried through the pipelines.
type Tarball struct {
	Bytes []byte
}

// PipelineContext is the shared state passed through every pipeline. The
// registry-specific metadata (Index) and matched artifact (Artifact) are
// `any`; each adapter's middleware asserts them to its concrete types
// (e.g. npm: *npm.Packument / *npm.Version; pypi: *pypi.Project / *pypi.File).
type PipelineContext struct {
	Ctx        context.Context
	Log        *slog.Logger
	Registry   string
	PkgName    string
	Version    string
	ArtifactID string // pypi: filename; maven: "classifier:type"; npm: "" (name+version suffices)
	ProjectKey string // tenant/project key from a "/p/<key>/..." request path; "" on the default (non-project) path
	Index      any    // registry-specific metadata document
	Artifact   any    // registry-specific matched artifact ref
	Tarball    *Tarball
	Metadata   map[string]any
}

// NewPipelineContext constructs a context with a background ctx if none is
// provided and an initialized Metadata map.
func NewPipelineContext(ctx context.Context, log *slog.Logger, registryName, pkg, version, artifactID string) *PipelineContext {
	if ctx == nil {
		ctx = context.Background()
	}
	// ProjectKey starts as "" — the default (non-project) path. Adapters that
	// support project routing set it from the request context after building.
	return &PipelineContext{
		Ctx:        ctx,
		Log:        log,
		Registry:   registryName,
		PkgName:    pkg,
		Version:    version,
		ArtifactID: artifactID,
		Metadata:   map[string]any{},
	}
}
