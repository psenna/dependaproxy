// Package pipeline is DependaProxy's orchestration core: it defines the
// validation/retrieval/mutation middleware contracts, the registry that maps
// config `type:` strings to middleware factories, and the runners that drive
// the chains. Concrete middleware live in internal/middleware/* and implement
// these interfaces (they import this package; this package does not import
// them, so there is no import cycle).
package pipeline

import (
	"context"
	"log/slog"

	"github.com/psenna/dependaproxy/internal/registry"
)

// Tarball is the package artifact carried through the pipelines.
type Tarball struct {
	Bytes []byte
}

// PipelineContext is the shared state passed through every pipeline. Each
// middleware may read it and may populate fields for downstream middleware.
type PipelineContext struct {
	Ctx       context.Context
	Log       *slog.Logger
	Registry  string
	PkgName   string
	Version   string
	Packument *registry.Packument
	Tarball   *Tarball
	Metadata  map[string]any
}

// NewPipelineContext constructs a context with a background ctx if none is
// provided and an initialized Metadata map.
func NewPipelineContext(ctx context.Context, log *slog.Logger, registryName, pkg, version string) *PipelineContext {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PipelineContext{
		Ctx:      ctx,
		Log:      log,
		Registry: registryName,
		PkgName:  pkg,
		Version:  version,
		Metadata: map[string]any{},
	}
}
