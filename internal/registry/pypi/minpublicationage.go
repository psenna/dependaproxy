package pypi

import (
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// minPubAge rejects a file if its upload-time age is below MinDays, reading the
// per-file PEP 700 upload-time from the matched File.
type minPubAge struct {
	minDays int
	now     func() time.Time
}

// Name returns the config type string.
func (minPubAge) Name() string { return "min-publication-age" }

// Validate fails closed: if the matched file or its upload-time is unavailable,
// the file is rejected (we cannot prove it is old enough). MinDays <= 0 disables.
func (m minPubAge) Validate(ctx *pipeline.PipelineContext) error {
	if m.minDays <= 0 {
		return nil
	}
	f, ok := ctx.Artifact.(*File)
	if !ok || f == nil {
		return fmt.Errorf("min-publication-age: file metadata unavailable for %s/%s", ctx.PkgName, ctx.ArtifactID)
	}
	if f.UploadTime.IsZero() {
		return fmt.Errorf("min-publication-age: no upload-time for %s/%s (fail-closed)", ctx.PkgName, ctx.ArtifactID)
	}
	age := m.now().UTC().Sub(f.UploadTime)
	if age < time.Duration(m.minDays)*24*time.Hour {
		return fmt.Errorf("min-publication-age: %s/%s uploaded %s ago, requires at least %d days",
			ctx.PkgName, ctx.ArtifactID, age.Round(time.Second), m.minDays)
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

// NewMinPub constructs a min-publication-age middleware with an injectable clock.
func NewMinPub(minDays int, now func() time.Time) minPubAge {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return minPubAge{minDays: minDays, now: now}
}
