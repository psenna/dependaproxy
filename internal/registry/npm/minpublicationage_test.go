package npm

import (
	"context"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
)

var fixedNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

func packument(version string, pub time.Time) *Packument {
	return &Packument{Time: map[string]time.Time{version: pub}}
}

func pctx(version string, p *Packument) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Ctx: context.Background(), Registry: "npm", PkgName: "pkg", Version: version, Index: p}
}

func TestMinPubRejectsRecent(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	pub := fixedNow.AddDate(0, 0, -3)
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", pub))); err == nil {
		t.Fatal("want reject for 3-day-old with min_days=7")
	}
}

func TestMinPubAcceptsOld(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", fixedNow.AddDate(0, 0, -10)))); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
}

func TestMinPubMissingTimeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("2.0.0", fixedNow.AddDate(0, 0, -30)))); err == nil {
		t.Fatal("want reject when time missing (fail-closed)")
	}
}

func TestMinPubZeroTimeRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", time.Time{}))); err == nil {
		t.Fatal("want reject for zero time (fail-closed)")
	}
}

func TestMinPubNilIndexRejected(t *testing.T) {
	m := NewMinPub(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", nil)); err == nil {
		t.Fatal("want reject when index is nil")
	}
}

func TestMinPubZeroDaysAlwaysAccept(t *testing.T) {
	m := NewMinPub(0, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", fixedNow))); err != nil {
		t.Fatalf("min_days=0 should accept, got %v", err)
	}
	if err := m.Validate(pctx("1.0.0", nil)); err != nil {
		t.Fatalf("min_days=0 should accept nil index, got %v", err)
	}
}
