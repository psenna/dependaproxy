package pypi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

type pFakeClient struct {
	project    *Project
	raw        []byte
	file       []byte
	indexErr   error
	fileErr    error
	indexCalls int32
	fileCalls  int32
}

func (f *pFakeClient) FetchIndex(_ context.Context, _ string) (*Project, error) {
	f.indexCalls++
	if f.indexErr != nil {
		return nil, f.indexErr
	}
	return f.project, nil
}
func (f *pFakeClient) FetchIndexRaw(_ context.Context, _ string, _ string) ([]byte, string, error) {
	return f.raw, acceptJSON, nil
}
func (f *pFakeClient) FetchAttestations(_ context.Context, _, _ string) ([]byte, error) {
	return nil, ErrNotFound
}
func (f *pFakeClient) FetchFile(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	f.fileCalls++
	if f.fileErr != nil {
		return nil, 0, f.fileErr
	}
	return io.NopCloser(bytes.NewReader(f.file)), int64(len(f.file)), nil
}

func pCtx(filename string, idx *Project) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "pypi", PkgName: "pkg", ArtifactID: filename, Index: idx}
}

func TestPUpstreamPopulates(t *testing.T) {
	proj := &Project{Name: "pkg", Files: []File{{Filename: "pkg-1.0.0-py3-none-any.whl", URL: "u/f.whl"}}}
	c := &pFakeClient{project: proj, file: []byte("BYTES")}
	u := NewUpstream(c)
	ctx := pCtx("pkg-1.0.0-py3-none-any.whl", nil)
	hit, err := u.Fetch(ctx)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if ctx.Index == nil || ctx.Artifact == nil || ctx.Tarball == nil {
		t.Errorf("ctx not populated: idx=%v art=%v tar=%v", ctx.Index, ctx.Artifact, ctx.Tarball)
	}
	if string(ctx.Tarball.Bytes) != "BYTES" {
		t.Errorf("tarball = %q", ctx.Tarball.Bytes)
	}
	if c.indexCalls != 1 {
		t.Errorf("indexCalls = %d want 1", c.indexCalls)
	}
}

func TestPUpstreamMissingFile(t *testing.T) {
	proj := &Project{Name: "pkg", Files: []File{}}
	c := &pFakeClient{project: proj}
	_, err := NewUpstream(c).Fetch(pCtx("nope.whl", nil))
	if err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestPUpstreamIndexNotFound(t *testing.T) {
	c := &pFakeClient{indexErr: ErrNotFound}
	_, err := NewUpstream(c).Fetch(pCtx("f.whl", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestPUpstreamSha256Mismatch(t *testing.T) {
	proj := &Project{Name: "pkg", Files: []File{{Filename: "f.whl", URL: "u/f.whl", Hashes: map[string]string{"sha256": "deadbeef"}}}}
	c := &pFakeClient{project: proj, file: []byte("BYTES")}
	_, err := NewUpstream(c).Fetch(pCtx("f.whl", nil))
	if err == nil {
		t.Fatal("want error for upstream sha256 mismatch")
	}
}
