package denylist

import (
	"bytes"
	"fmt"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// name is the config type string for the deny-list-check middleware.
const name = "deny-list-check"

// Params is the yaml-decoded configuration for the deny-list-check middleware.
type Params struct {
	// Enabled defaults to true when the middleware is listed. It is a *bool so
	// an unset param (nil, default true) is distinguishable from an explicit
	// false.
	Enabled *bool `yaml:"enabled"`
}

// checkMiddleware consults the persistent deny list at the start of the
// validation pipeline. A previously-denied (registry, name, version, sha256,
// project_key) short-circuits the chain with the stored reason, skipping the
// expensive guarddog/malware subprocess scans.
type checkMiddleware struct {
	store   Store
	enabled bool
}

// Name returns the config type string.
func (*checkMiddleware) Name() string { return name }

// Validate denies the package immediately when a denial is already recorded
// for its exact scope. Matching is strict per project: the store blocks only
// the project (or projectless scope) that recorded the denial, and this
// middleware passes ctx.ProjectKey through unchanged so the lookup never
// crosses scopes. Store and hashing failures fail open: a deny-list outage
// must not block serving — the downstream validation chain remains the
// authoritative gate.
func (m *checkMiddleware) Validate(ctx *pipeline.PipelineContext) error {
	if !m.enabled || m.store == nil {
		return nil
	}
	if ctx.Tarball == nil || len(ctx.Tarball.Bytes) == 0 {
		// Defensive; validation runs after retrieval so the tarball is present.
		return nil
	}
	h, ok := ctx.Sha256FromMetadata()
	if !ok {
		// Defensive fallback: serveUntrusted stashes the hash before running the
		// validation chain, so this is only reachable for direct callers (tests)
		// or future non-serveUntrusted uses. Recompute to keep behavior identical.
		var err error
		h, _, err = hash.Sha256Hex(bytes.NewReader(ctx.Tarball.Bytes))
		if err != nil {
			if ctx.Log != nil {
				ctx.Log.Warn("deny-list-check: hashing artifact failed; serving (fail_open)", "err", err)
			}
			return nil
		}
	}
	reason, ok, err := m.store.Lookup(ctx.Ctx, ctx.Registry, ctx.PkgName, ctx.Version, h, ctx.ProjectKey)
	if err != nil {
		if ctx.Log != nil {
			ctx.Log.Warn("deny-list-check: deny list unavailable; serving (fail_open)", "err", err)
		}
		return nil
	}
	if ok {
		return fmt.Errorf("deny-list-check: %s@%s previously denied: %s", ctx.PkgName, ctx.Version, reason)
	}
	return nil
}

// Factory builds the deny-list-check middleware from its raw params node,
// mirroring guarddog.Factory. The store is injected so tests can substitute a
// fake. Enabled defaults to true when the middleware is listed.
func Factory(s Store) pipeline.ValidationFactory {
	return func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
		var pr Params
		if !p.IsZero() {
			if err := p.Decode(&pr); err != nil {
				return nil, fmt.Errorf("%s: decode params: %w", name, err)
			}
		}
		enabled := true
		if pr.Enabled != nil {
			enabled = *pr.Enabled
		}
		return &checkMiddleware{store: s, enabled: enabled}, nil
	}
}
