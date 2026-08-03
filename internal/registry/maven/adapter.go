package maven

import (
	"net/http"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
)

func init() { adapter.Register("maven", Factory) }

// mavenAdapter is the v2 Maven skeleton adapter. Its handler returns 501 for
// every request — full routing/storage/validation land in a future issue.
type mavenAdapter struct{ prefix string }

// Prefix returns the URL path prefix.
func (a *mavenAdapter) Prefix() string { return a.prefix }

// InvalidateProjectCache is a no-op: the maven skeleton has no resolver yet.
func (a *mavenAdapter) InvalidateProjectCache(string) {}

// Handler serves a 501 placeholder (Maven adapter not yet implemented).
func (a *mavenAdapter) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte("maven adapter not implemented\n"))
	})
}

// Factory builds the maven skeleton adapter.
func Factory(cfg config.RegistryConfig, _ adapter.Deps) (adapter.Adapter, error) {
	return &mavenAdapter{prefix: cfg.Prefix}, nil
}
