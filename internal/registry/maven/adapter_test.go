package maven

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/psenna/dependaproxy/internal/adapter"
	"github.com/psenna/dependaproxy/internal/config"
)

func closeBody(c io.Closer) { _ = c.Close() }

func TestMavenFactoryReturns501(t *testing.T) {
	a, err := Factory(context.Background(), config.RegistryConfig{Type: "maven", Prefix: "/maven", Upstream: "u"}, adapter.Deps{})
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	if a.Prefix() != "/maven" {
		t.Fatalf("prefix = %q", a.Prefix())
	}
	srv := httptest.NewServer(http.StripPrefix(a.Prefix(), a.Handler()))
	t.Cleanup(srv.Close)
	for _, p := range []string{"/maven/foo", "/maven/com/acme/lib/1.0/lib-1.0.jar"} {
		resp, err := http.Get(srv.URL + p) //nolint:gosec // G107: test URL
		if err != nil {
			t.Fatal(err)
		}
		closeBody(resp.Body)
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("GET %s: status = %d, want 501", p, resp.StatusCode)
		}
	}
}

func TestMavenMetadataParse(t *testing.T) {
	src := []byte(`<metadata><groupId>com.acme</groupId><artifactId>lib</artifactId>
<versioning><latest>1.2</latest><release>1.2</release><versions><version>1.0</version><version>1.2</version></versions><lastUpdated>20200101000000</lastUpdated></versioning></metadata>`)
	var m Metadata
	if err := xml.Unmarshal(src, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.GroupID != "com.acme" || m.ArtifactID != "lib" || m.Versioning.Latest != "1.2" || len(m.Versioning.Versions) != 2 {
		t.Errorf("metadata = %+v", m)
	}
}
