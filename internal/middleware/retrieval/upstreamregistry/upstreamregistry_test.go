package upstreamregistry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
)

type fakeClient struct {
	packument *registry.Packument
	tarball   []byte
	packErr   error
	tarErr    error
	packCalls int
	tarCalls  int
}

func (f *fakeClient) FetchPackument(_ context.Context, _ string) (*registry.Packument, error) {
	f.packCalls++
	if f.packErr != nil {
		return nil, f.packErr
	}
	return f.packument, nil
}

func (f *fakeClient) FetchPackumentRaw(_ context.Context, _ string) ([]byte, error) {
	return nil, nil // unused by the upstream-registry middleware
}

func (f *fakeClient) FetchTarball(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	f.tarCalls++
	if f.tarErr != nil {
		return nil, 0, f.tarErr
	}
	return io.NopCloser(bytes.NewReader(f.tarball)), int64(len(f.tarball)), nil
}

func newCtx(pkg, ver string, pack *registry.Packument) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: pkg, Version: ver, Packument: pack}
}

func TestFetchPopulatesPackumentAndTarball(t *testing.T) {
	pack := &registry.Packument{
		Name:     "pkg",
		Versions: map[string]registry.Version{"1.0.0": {Version: "1.0.0", Dist: registry.Dist{Tarball: "u/pkg-1.0.0.tgz"}}},
	}
	c := &fakeClient{packument: pack, tarball: []byte("BYTES")}
	m := New(c)
	ctx := newCtx("pkg", "1.0.0", nil)
	hit, err := m.Fetch(ctx)
	if err != nil || !hit {
		t.Fatalf("hit=%v err=%v", hit, err)
	}
	if ctx.Packument == nil || ctx.Packument.Name != "pkg" {
		t.Errorf("packument not populated: %+v", ctx.Packument)
	}
	if ctx.Tarball == nil || string(ctx.Tarball.Bytes) != "BYTES" {
		t.Errorf("tarball = %q", ctx.Tarball)
	}
	if c.packCalls != 1 {
		t.Errorf("packument calls = %d want 1", c.packCalls)
	}
}

func TestFetchReusesExistingPackument(t *testing.T) {
	pack := &registry.Packument{
		Versions: map[string]registry.Version{"1.0.0": {Dist: registry.Dist{Tarball: "u/t.tgz"}}},
	}
	c := &fakeClient{packument: pack, tarball: []byte("B")}
	m := New(c)
	ctx := newCtx("pkg", "1.0.0", pack) // already populated
	if _, err := m.Fetch(ctx); err != nil {
		t.Fatalf("err: %v", err)
	}
	if c.packCalls != 0 {
		t.Errorf("should not refetch packument, calls=%d", c.packCalls)
	}
	if c.tarCalls != 1 {
		t.Errorf("should fetch tarball, calls=%d", c.tarCalls)
	}
}

func TestFetchAbsentVersion(t *testing.T) {
	pack := &registry.Packument{Versions: map[string]registry.Version{}}
	c := &fakeClient{packument: pack, tarball: nil}
	m := New(c)
	_, err := m.Fetch(newCtx("pkg", "9.9.9", nil))
	if err == nil {
		t.Fatal("want error for absent version")
	}
}

func TestFetchPackumentNotFound(t *testing.T) {
	c := &fakeClient{packErr: registry.ErrNotFound}
	m := New(c)
	_, err := m.Fetch(newCtx("pkg", "1.0.0", nil))
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}

func TestFetchTarballNotFound(t *testing.T) {
	pack := &registry.Packument{Versions: map[string]registry.Version{"1.0.0": {Dist: registry.Dist{Tarball: "u/t.tgz"}}}}
	c := &fakeClient{packument: pack, tarErr: registry.ErrNotFound}
	m := New(c)
	_, err := m.Fetch(newCtx("pkg", "1.0.0", nil))
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v want ErrNotFound", err)
	}
}
