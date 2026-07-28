package minpublicationage

import (
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/registry"
	"gopkg.in/yaml.v3"
)

var fixedNow = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

func packument(version string, pub time.Time) *registry.Packument {
	return &registry.Packument{Time: map[string]time.Time{version: pub}}
}

func pctx(version string, p *registry.Packument) *pipeline.PipelineContext {
	return &pipeline.PipelineContext{Registry: "npm", PkgName: "pkg", Version: version, Packument: p}
}

func TestRejectsRecent(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	pub := fixedNow.AddDate(0, 0, -3) // 3 days old
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", pub))); err == nil {
		t.Fatal("want rejection for 3-day-old package with min_days=7")
	}
}

func TestAcceptsOld(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	pub := fixedNow.AddDate(0, 0, -10) // 10 days old
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", pub))); err != nil {
		t.Fatalf("want accept for 10-day-old, got %v", err)
	}
}

func TestAcceptsAtThreshold(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	pub := fixedNow.Add(-7 * 24 * time.Hour) // exactly 7 days
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", pub))); err != nil {
		t.Fatalf("want accept at exactly min_days, got %v", err)
	}
}

func TestRejectsJustBelowThreshold(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	pub := fixedNow.Add(-7*24*time.Hour + time.Second) // 7 days minus 1s
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", pub))); err == nil {
		t.Fatal("want rejection just below threshold")
	}
}

func TestMissingTimeRejected(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	// packument has no time entry for the requested version.
	if err := m.Validate(pctx("1.0.0", packument("2.0.0", fixedNow.AddDate(0, 0, -30)))); err == nil {
		t.Fatal("want rejection when publication time is missing (fail-closed)")
	}
}

func TestZeroPublicationTimeRejected(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", time.Time{}))); err == nil {
		t.Fatal("want rejection for zero publication time (fail-closed)")
	}
}

func TestNilPackumentRejected(t *testing.T) {
	m := New(7, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", nil)); err == nil {
		t.Fatal("want rejection when packument is nil (fail-closed)")
	}
}

func TestMinDaysZeroAlwaysAccept(t *testing.T) {
	m := New(0, func() time.Time { return fixedNow })
	if err := m.Validate(pctx("1.0.0", packument("1.0.0", fixedNow))); err != nil {
		t.Fatalf("min_days=0 should always accept, got %v", err)
	}
	if err := m.Validate(pctx("1.0.0", nil)); err != nil {
		t.Fatalf("min_days=0 should accept even nil packument, got %v", err)
	}
}

func TestFactoryDecodesMinDays(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("min_days: 14"), &node); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(node)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	m := mw.(Middleware)
	if m.minDays != 14 {
		t.Errorf("minDays = %d want 14", m.minDays)
	}
}

func TestFactoryEmptyParams(t *testing.T) {
	mw, err := Factory(yaml.Node{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if mw.(Middleware).minDays != 0 {
		t.Errorf("empty params should default minDays to 0")
	}
}

func TestFactoryBadParams(t *testing.T) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("min_days: not-a-number"), &node); err != nil {
		t.Fatal(err)
	}
	if _, err := Factory(node); err == nil {
		t.Fatal("want error for bad params")
	}
}
