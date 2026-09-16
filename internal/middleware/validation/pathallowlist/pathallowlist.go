// Package pathallowlist implements a validation middleware that denies a
// request whose ctx.PkgName does not match any of a configured set of glob
// patterns. It is registry-agnostic (any adapter can register it), built for
// the oci adapter's per-upstream repository-path allowlisting but not
// specific to it.
package pathallowlist

import (
	"fmt"
	"path"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Middleware denies ctx.PkgName unless it matches at least one pattern.
type Middleware struct {
	patterns []string
}

// Name returns the config type string.
func (*Middleware) Name() string { return "path-allowlist" }

// Validate matches ctx.PkgName against each configured pattern with Go's
// path.Match (shell-glob "*" semantics, "*" does not cross a "/"). The first
// match allows the request; no match denies it.
func (m *Middleware) Validate(ctx *pipeline.PipelineContext) error {
	for _, p := range m.patterns {
		ok, err := path.Match(p, ctx.PkgName)
		if err != nil {
			// Malformed patterns are rejected at New()/Factory() time, not
			// here -- a pattern that got this far is always well-formed, so
			// this branch is unreachable in practice. Fail closed anyway.
			return fmt.Errorf("path-allowlist: pattern %q: %w", p, err)
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("path-allowlist: %q does not match any allowed pattern", ctx.PkgName)
}

// New validates every pattern (path.Match rejects a malformed one) and
// constructs a Middleware. An empty patterns list is rejected: it would deny
// every request, which is never the intended configuration -- an operator who
// wants a fully closed registry should not enable it at all.
func New(patterns []string) (*Middleware, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("path-allowlist: patterns must not be empty")
	}
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("path-allowlist: invalid pattern %q: %w", p, err)
		}
	}
	return &Middleware{patterns: patterns}, nil
}

type params struct {
	Patterns []string `yaml:"patterns"`
}

// Factory builds the middleware from its raw params node, registered by an
// adapter under "path-allowlist".
var Factory pipeline.ValidationFactory = func(p yaml.Node) (pipeline.ValidationMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("path-allowlist: decode params: %w", err)
		}
	}
	return New(pr.Patterns)
}
