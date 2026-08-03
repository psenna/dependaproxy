package goproxy

import (
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// minPubAge rejects a module version if its publication age is below MinDays,
// reading the GOPROXY .info (*Info) publication Time stashed in ctx.Index by
// the upstream-registry retrieval.
type minPubAge struct {
	minDays int
	now     func() time.Time
}

// Name returns the config type string.
func (minPubAge) Name() string { return "min-publication-age" }

// Validate fails closed: if the *Info or its publication time is unavailable,
// the module version is rejected. MinDays <= 0 disables the check.
func (m minPubAge) Validate(ctx *pipeline.PipelineContext) error {
	if m.minDays <= 0 {
		return nil
	}
	info, ok := ctx.Index.(*Info)
	if !ok || info == nil || info.Time.IsZero() {
		return fmt.Errorf("min-publication-age: no publication time for %s@%s (fail-closed)", ctx.PkgName, ctx.Version)
	}
	age := m.now().UTC().Sub(info.Time)
	if age < time.Duration(m.minDays)*24*time.Hour {
		return fmt.Errorf("min-publication-age: %s@%s published %s ago, requires at least %d days",
			ctx.PkgName, ctx.Version, age.Round(time.Second), m.minDays)
	}
	return nil
}

type minPubParams struct {
	MinDays int `yaml:"min_days"`
}

// MinPubFactory builds the middleware from its raw params node, registered as
// "min-publication-age".
var MinPubFactory pipeline.ValidationFactory = func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
	var pr minPubParams
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("min-publication-age: decode params: %w", err)
		}
	}
	return minPubAge{minDays: pr.MinDays, now: func() time.Time { return time.Now().UTC() }}, nil
}

// NewMinPub constructs a min-publication-age middleware with an injectable clock
// for deterministic tests.
func NewMinPub(minDays int, now func() time.Time) minPubAge {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return minPubAge{minDays: minDays, now: now}
}
