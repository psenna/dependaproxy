// Package upstreamregistry implements the terminal retrieval middleware that
// fetches packages from the upstream npm registry. It is the last link in the
// retrieval decorator chain (it does not call next).
package upstreamregistry

import (
	"fmt"
	"io"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
	"gopkg.in/yaml.v3"
)

// Middleware fetches the packument (if not already present) and the tarball from
// the upstream registry. It is terminal and ignores next.
type Middleware struct {
	client registry.RegistryClient
}

// New returns a terminal upstream-registry middleware bound to client.
func New(client registry.RegistryClient) Middleware {
	return Middleware{client: client}
}

// Name returns the config type string.
func (Middleware) Name() string { return "upstream-registry" }

// Fetch populates ctx.Packument (if nil) and ctx.Tarball from the upstream
// registry. It returns (true, nil) on success. A missing version or an upstream
// 404 (ErrNotFound) is propagated as an error.
func (m Middleware) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	if ctx.Packument == nil {
		p, err := m.client.FetchPackument(ctx.Ctx, ctx.PkgName)
		if err != nil {
			return false, err
		}
		ctx.Packument = p
	}
	ver, ok := ctx.Packument.Versions[ctx.Version]
	if !ok {
		return false, fmt.Errorf("upstream-registry: version %s not found for %s", ctx.Version, ctx.PkgName)
	}
	if ctx.Tarball == nil {
		rc, _, err := m.client.FetchTarball(ctx.Ctx, ver.Dist.Tarball)
		if err != nil {
			return false, err
		}
		defer rc.Close() //nolint:errcheck // cleanup of a streamed upstream body
		b, err := io.ReadAll(rc)
		if err != nil {
			return false, fmt.Errorf("upstream-registry: read tarball: %w", err)
		}
		ctx.Tarball = &pipeline.Tarball{Bytes: b}
	}
	return true, nil
}

// Factory returns a RetrievalFactory that binds client. The client is a runtime
// dependency (owned by the server), so the server builds this closure rather
// than the registry constructing it from config alone.
func Factory(client registry.RegistryClient) pipeline.RetrievalFactory {
	return func(_ yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
		return New(client), nil
	}
}
