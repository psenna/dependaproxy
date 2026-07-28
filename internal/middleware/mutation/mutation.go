// Package mutation provides mutation middleware implementations. v1 ships a
// single NoOp so the server's PreFetch/PostFetch hook path is exercised; real
// mutations (remove-install-scripts, etc.) are added later without server
// changes.
package mutation

import (
	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// NoOp is a mutation middleware that does nothing in either hook.
type NoOp struct{}

// Name returns the middleware name.
func (NoOp) Name() string { return "noop" }

// PreFetch is a no-op.
func (NoOp) PreFetch(*pipeline.PipelineContext) error { return nil }

// PostFetch is a no-op.
func (NoOp) PostFetch(*pipeline.PipelineContext) error { return nil }

// Factory builds a NoOp. Registered by the server as "noop".
var Factory pipeline.MutationFactory = func(_ yaml.Node) (pipeline.MutationMiddleware, error) {
	return NoOp{}, nil
}
