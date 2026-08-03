package goproxy

import (
	"context"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

var fixedNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

func pctx(version string, idx any) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "goproxy", PkgName: "github.com/acme/mod", Version: version, Index: idx}
}

func TestMinPubRejectsRecent(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	idx := &Info{Version: "v1.0.0", Time: fixedNow.AddDate(0, 0, -3)}
	if err := m.Validate(pctx("v1.0.0", idx)); err == nil {
		t.Fatal("want reject for 3-day-old with min_days=7")
	}
}

func TestMinPubAcceptsOld(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	idx := &Info{Version: "v1.0.0", Time: fixedNow.AddDate(0, 0, -10)}
	if err := m.Validate(pctx("v1.0.0", idx)); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}

func TestMinPubMissingTimeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("v1.0.0", nil)); err == nil {
		t.Fatal("want reject when index is nil (fail-closed)")
	}
}

func TestMinPubZeroTimeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	idx := &Info{Version: "v1.0.0", Time: time.Time{}}
	if err := m.Validate(pctx("v1.0.0", idx)); err == nil {
		t.Fatal("want reject for zero time (fail-closed)")
	}
}

func TestMinPubWrongTypeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("v1.0.0", "not an *Info")); err == nil {
		t.Fatal("want reject when index is not an *Info (fail-closed)")
	}
}

func TestMinPubZeroDaysAlwaysAccept(t *testing.T) {
	m := NewMinPub(0, func() time.Time { return fixedNow })
	idx := &Info{Version: "v1.0.0", Time: fixedNow}
	if err := m.Validate(pctx("v1.0.0", idx)); err != nil {
		t.Fatalf("min_days=0 should accept, got %v", err)
	}
	if err := m.Validate(pctx("v1.0.0", nil)); err != nil {
		t.Fatalf("min_days=0 should accept nil index, got %v", err)
	}
}
