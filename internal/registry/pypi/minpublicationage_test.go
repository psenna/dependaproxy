package pypi

import (
	"context"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

var pFixedNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

func pctx(filename string, f *File) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "pypi", PkgName: "pkg", ArtifactID: filename, Artifact: f}
}

func fileAt(pub time.Time) *File { return &File{Filename: "f.whl", UploadTime: pub} }

func TestPMinPubRejectsFresh(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return pFixedNow })
	if err := m.Validate(pctx("f.whl", fileAt(pFixedNow.AddDate(0, 0, -3)))); err == nil {
		t.Fatal("want reject for 3-day-old")
	}
}

func TestPMinPubAcceptsOld(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return pFixedNow })
	if err := m.Validate(pctx("f.whl", fileAt(pFixedNow.AddDate(0, 0, -10)))); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}

func TestPMinPubZeroTimeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return pFixedNow })
	if err := m.Validate(pctx("f.whl", &File{Filename: "f.whl"})); err == nil { // zero UploadTime
		t.Fatal("want reject for zero upload-time (fail-closed)")
	}
}

func TestPMinPubNilArtifactRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return pFixedNow })
	if err := m.Validate(pctx("f.whl", nil)); err == nil {
		t.Fatal("want reject when artifact is nil")
	}
}

func TestPMinPubZeroDaysAlwaysAccept(t *testing.T) {
	m := NewMinPub(0, func() time.Time { return pFixedNow })
	if err := m.Validate(pctx("f.whl", fileAt(pFixedNow))); err != nil {
		t.Fatalf("min_days=0 should accept, got %v", err)
	}
}
