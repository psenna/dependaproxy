package pypi

import (
	"bytes"
	"fmt"
	"io"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// upstreamRegistry is the terminal retrieval middleware that fetches from the
// upstream PyPI simple index. It populates ctx.Index (*Project), ctx.Artifact
// (the matched *File for ctx.ArtifactID), and ctx.Tarball.
type upstreamRegistry struct {
	client RegistryClient
}

// NewUpstream returns a terminal upstream-registry middleware bound to client.
func NewUpstream(client RegistryClient) *upstreamRegistry { return &upstreamRegistry{client: client} }

// Name returns the config type string.
func (*upstreamRegistry) Name() string { return "upstream-registry" }

// Fetch resolves the requested file. A missing file or upstream 404
// (ErrNotFound) is propagated as an error. As defense-in-depth, if the
// upstream advertises a sha256 for the file, the fetched bytes are verified
// against it (mismatch -> error, never served).
func (u *upstreamRegistry) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	proj, _ := ctx.Index.(*Project)
	if proj == nil { // covers untyped-nil and typed-nil *Project
		p, err := u.client.FetchIndex(ctx.Ctx, ctx.PkgName)
		if err != nil {
			return false, err
		}
		ctx.Index = p
		proj = p
	}
	var match *File
	for i := range proj.Files {
		if proj.Files[i].Filename == ctx.ArtifactID {
			match = &proj.Files[i]
			break
		}
	}
	if match == nil {
		return false, fmt.Errorf("upstream-registry: file %s not found for %s", ctx.ArtifactID, ctx.PkgName)
	}
	ctx.Artifact = match
	if ctx.Tarball == nil {
		rc, _, err := u.client.FetchFile(ctx.Ctx, match.URL)
		if err != nil {
			return false, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(rc)
		if err != nil {
			return false, fmt.Errorf("upstream-registry: read file %s: %w", ctx.ArtifactID, err)
		}
		if wantSHA, ok := match.Hashes["sha256"]; ok && wantSHA != "" {
			if ok, _, err := hash.VerifyHex(wantSHA, bytes.NewReader(b)); err == nil && !ok {
				return false, fmt.Errorf("upstream-registry: upstream sha256 mismatch for %s", ctx.ArtifactID)
			}
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
