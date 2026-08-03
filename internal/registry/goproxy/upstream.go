package goproxy

import (
	"fmt"
	"io"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// upstreamRegistry is the terminal retrieval middleware that fetches from the
// upstream Go module proxy. It populates ctx.Index (*Info) and ctx.Tarball.
type upstreamRegistry struct {
	client RegistryClient
}

// NewUpstream returns a terminal upstream-registry middleware bound to client.
func NewUpstream(client RegistryClient) *upstreamRegistry { return &upstreamRegistry{client: client} }

// Name returns the config type string.
func (*upstreamRegistry) Name() string { return "upstream-registry" }

// Fetch populates ctx.Index (if not already an *Info) and ctx.Tarball from
// upstream. A missing version or upstream 404 (ErrNotFound) is propagated as
// an error.
func (u *upstreamRegistry) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	if _, ok := ctx.Index.(*Info); !ok {
		info, err := u.client.FetchInfo(ctx.Ctx, ctx.PkgName, ctx.Version)
		if err != nil {
			return false, err
		}
		ctx.Index = info
	}
	if ctx.Tarball == nil {
		rc, _, err := u.client.FetchZip(ctx.Ctx, ctx.PkgName, ctx.Version)
		if err != nil {
			return false, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		if err != nil {
			return false, fmt.Errorf("upstream-registry: read zip: %w", err)
		}
		ctx.Tarball = &pipeline.Tarball{Bytes: b}
	}
	return true, nil
}

// UpstreamFactory returns a RetrievalFactory bound to client, registered as
// "upstream-registry".
func UpstreamFactory(client RegistryClient) pipeline.RetrievalFactory {
	return func(_ yaml.Node, _ pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
		return NewUpstream(client), nil
	}
}
