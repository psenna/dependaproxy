package npm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

type fakeClient struct {
	packument *Packument
	tarball   []byte
	packErr   error
	tarErr    error
	packCalls int32
	tarCalls  int32
}

func (f *fakeClient) FetchPackument(_ context.Context, _ string) (*Packument, error) {
	f.packCalls++
	if f.packErr != nil {
		return nil, f.packErr
	}
	return f.packument, nil
}
func (f *fakeClient) FetchPackumentRaw(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (f *fakeClient) FetchBytes(_ context.Context, _ string) ([]byte, error) { return nil, ErrNotFound }
func (f *fakeClient) FetchTarball(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	f.tarCalls++
	if f.tarErr != nil {
		return nil, 0, f.tarErr
	}
	return io.NopCloser(bytes.NewReader(f.tarball)), int64(len(f.tarball)), nil
}

func newCtx(pkg, ver string, idx *Packument) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: pkg, Version: ver, Index: idx}
}

func TestUpstreamPopulatesIndexAndTarball(t *testing.T) {
	pack := &Packument{Name: "pkg", Versions: map[string]Version{"1.0.0": {Version: "1.0.0", Dist: Dist{Tarball: "u/t.tgz"}}}}
	c := &fakeClient{packument: pack, tarball: []byte("BYTES")}
	u := NewUpstream(c)
	ctx := newCtx("pkg", "1.0.0", nil)
	hit, err := u.Fetch(ctx)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if ctx.Index == nil || ctx.Index.(*Packument).Name != "pkg" {
		t.Errorf("index not populated: %v", ctx.Index)
	}
	if ctx.Tarball == nil || string(ctx.Tarball.Bytes) != "BYTES" {
		t.Errorf("tarball = %v", ctx.Tarball)
	}
	if c.packCalls != 1 {
		t.Errorf("packument calls = %d want 1", c.packCalls)
	}
}

func TestUpstreamReusesExistingIndex(t *testing.T) {
	pack := &Packument{Versions: map[string]Version{"1.0.0": {Dist: Dist{Tarball: "u/t.tgz"}}}}
	c := &fakeClient{packument: pack, tarball: []byte("B")}
	u := NewUpstream(c)
	ctx := newCtx("pkg", "1.0.0", pack) // index already set
	if _, err := u.Fetch(ctx); err != nil {
		t.Fatalf("err: %v", err)
	}
	if c.packCalls != 0 {
		t.Errorf("should not refetch packument, calls=%d", c.packCalls)
	}
	if c.tarCalls != 1 {
		t.Errorf("should fetch tarball, calls=%d", c.tarCalls)
	}
}

func TestUpstreamAbsentVersion(t *testing.T) {
	c := &fakeClient{packument: &Packument{Versions: map[string]Version{}}}
	_, err := NewUpstream(c).Fetch(newCtx("pkg", "9.9.9", nil))
	if err == nil {
		t.Fatal("want error for absent version")
	}
}

func TestUpstreamPackumentNotFound(t *testing.T) {
	c := &fakeClient{packErr: ErrNotFound}
	_, err := NewUpstream(c).Fetch(newCtx("pkg", "1.0.0", nil))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}
