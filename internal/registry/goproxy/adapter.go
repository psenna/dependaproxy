package goproxy

import (
	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
)

func init() { adapter.Register("goproxy", Factory) }

// Factory builds the goproxy adapter from its RegistryConfig + shared Deps.
// The middleware lists are ignored (pass-through in v1 — maven precedent);
// storage/trust flow lands in a later issue.
func Factory(cfg config.RegistryConfig, deps adapter.Deps) (adapter.Adapter, error) {
	client, err := New(cfg.Upstream, nil)
	if err != nil {
		return nil, err
	}
	return &goproxyAdapter{prefix: cfg.Prefix, client: client, logger: deps.Logger, now: deps.Now}, nil
}
