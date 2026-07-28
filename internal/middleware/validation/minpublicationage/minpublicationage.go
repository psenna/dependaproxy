// Package minpublicationage implements the v1 validation middleware that
// rejects packages published less than a configurable number of days ago.
package minpublicationage

import (
	"fmt"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Middleware rejects a package if its publication age is below MinDays.
type Middleware struct {
	minDays int
	now     func() time.Time
}

// Name returns the config type string.
func (Middleware) Name() string { return "min-publication-age" }

// Validate fails closed: if the packument or the version's publication time is
// unavailable, the package is rejected (we cannot prove it is old enough).
// MinDays <= 0 disables the check (always accept).
func (m Middleware) Validate(ctx *pipeline.PipelineContext) error {
	if m.minDays <= 0 {
		return nil
	}
	if ctx.Packument == nil {
		return fmt.Errorf("min-publication-age: packument unavailable for %s@%s", ctx.PkgName, ctx.Version)
	}
	pub, ok := ctx.Packument.Time[ctx.Version]
	if !ok || pub.IsZero() {
		return fmt.Errorf("min-publication-age: no publication time for %s@%s", ctx.PkgName, ctx.Version)
	}
	now := m.now().UTC()
	age := now.Sub(pub)
	if age < time.Duration(m.minDays)*24*time.Hour {
		return fmt.Errorf("min-publication-age: %s@%s published %s ago, requires at least %d days",
			ctx.PkgName, ctx.Version, age.Round(time.Second), m.minDays)
	}
	return nil
}

type params struct {
	MinDays int `yaml:"min_days"`
}

// Factory builds the middleware from its raw params node. Registered by the
// server as "min-publication-age".
var Factory pipeline.ValidationFactory = func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
	pr, err := decodeParams(p)
	if err != nil {
		return nil, err
	}
	return Middleware{minDays: pr.MinDays, now: func() time.Time { return time.Now().UTC() }}, nil
}

// New constructs a middleware with an injectable clock (for deterministic
// tests). A nil now defaults to the current UTC time.
func New(minDays int, now func() time.Time) Middleware {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return Middleware{minDays: minDays, now: now}
}

func decodeParams(p yaml.Node) (params, error) {
	var pr params
	if p.IsZero() {
		return pr, nil
	}
	if err := p.Decode(&pr); err != nil {
		return pr, fmt.Errorf("min-publication-age: decode params: %w", err)
	}
	return pr, nil
}
