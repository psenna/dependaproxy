package pathallowlist

import (
	"context"
	"log/slog"
	"testing"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func testCtx(pkgName string) *pipeline.PipelineContext {
	return pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "oci/docker", pkgName, "latest", "")
}

func TestMiddleware_Validate(t *testing.T) {
	m, err := New([]string{"library/*", "bitnami/*"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cases := []struct {
		name    string
		pkg     string
		wantErr bool
	}{
		{"top-level match", "library/nginx", false},
		{"second pattern match", "bitnami/redis", false},
		{"no match", "someuser/nginx", true},
		{"pattern requires the segment present", "library", true},
		{"nested path under an allowed prefix", "library/nginx/extra", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.Validate(testCtx(tc.pkg))
			if tc.wantErr && err == nil {
				t.Errorf("Validate(%q) = nil, want an error", tc.pkg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.pkg, err)
			}
		})
	}
}

func TestMiddleware_Name(t *testing.T) {
	m, _ := New([]string{"library/*"})
	if got := m.Name(); got != "path-allowlist" {
		t.Errorf("Name() = %q, want %q", got, "path-allowlist")
	}
}

func TestNew_EmptyPatternsRejected(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want an error: an empty allowlist would deny everything, almost certainly not intended")
	}
	if _, err := New([]string{}); err == nil {
		t.Fatal("New([]string{}) = nil error, want an error")
	}
}

func TestNew_MalformedPatternRejected(t *testing.T) {
	if _, err := New([]string{"["}); err == nil {
		t.Fatal(`New([]string{"["}) = nil error, want an error: "[" is not a valid path.Match pattern`)
	}
}

func TestFactory(t *testing.T) {
	params := yaml.Node{}
	if err := params.Encode(struct {
		Patterns []string `yaml:"patterns"`
	}{Patterns: []string{"library/*"}}); err != nil {
		t.Fatal(err)
	}
	mw, err := Factory(params)
	if err != nil {
		t.Fatalf("Factory() error = %v", err)
	}
	if err := mw.Validate(testCtx("library/nginx")); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
	if err := mw.Validate(testCtx("someuser/nginx")); err == nil {
		t.Error("Validate() = nil, want an error")
	}
}

func TestFactory_EmptyParamsRejected(t *testing.T) {
	if _, err := Factory(yaml.Node{}); err == nil {
		t.Fatal("Factory(zero yaml.Node) = nil error, want an error (no patterns configured)")
	}
}
