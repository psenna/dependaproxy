package npm

import (
	"fmt"
	"io"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// upstreamRegistry is the terminal retrieval middleware that fetches from the
// upstream npm registry. It populates ctx.Index (*Packument) and ctx.Tarball.
type upstreamRegistry struct {
	client RegistryClient
}

// NewUpstream returns a terminal upstream-registry middleware bound to client.
func NewUpstream(client RegistryClient) *upstreamRegistry { return &upstreamRegistry{client: client} }

// Name returns the config type string.
func (*upstreamRegistry) Name() string { return "upstream-registry" }

// Fetch populates ctx.Index (if nil) and ctx.Tarball from upstream. A missing
// version or upstream 404 (ErrNotFound) is propagated as an error.
func (u *upstreamRegistry) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	pack, _ := ctx.Index.(*Packument)
	if pack == nil { // covers both untyped-nil and typed-nil *Packument
		p, err := u.client.FetchPackument(ctx.Ctx, ctx.PkgName)
		if err != nil {
			return false, err
		}
		ctx.Index = p
		pack = p
	}
	ver, ok := pack.Versions[ctx.Version]
	if !ok {
		return false, fmt.Errorf("upstream-registry: version %s not found for %s", ctx.Version, ctx.PkgName)
	}
	if ctx.Tarball == nil {
		rc, _, err := u.client.FetchTarball(ctx.Ctx, ver.Dist.Tarball)
		if err != nil {
			return false, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		if err != nil {
			return false, fmt.Errorf("upstream-registry: read tarball: %w", err)
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
