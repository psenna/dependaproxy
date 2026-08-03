package project_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/project"
	"github.com/psenna/dependaproxy/internal/storage/db"
	"gopkg.in/yaml.v3"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("DP_TEST_PG_DSN not set; skipping project postgres test")
	}
	return dsn
}

func openTestStore(t *testing.T) (*project.Storage, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	d, err := db.OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	st, err := project.OpenStore(ctx, d)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := d.ExecContext(ctx, `DELETE FROM projects`); err != nil {
		t.Fatalf("clean: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return st, d
}

func mwYAML(s string) yaml.Node {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		panic(err)
	}
	// Strip the document node: inline values (as a struct field unmarshal would
	// produce) must be a mapping/scalar node, not a document root, to round-trip
	// through yaml.Marshal.
	if len(n.Content) > 0 {
		return *n.Content[0]
	}
	return n
}

func sampleConfig(key string) project.ProjectConfig {
	return project.ProjectConfig{
		Key: key,
		Registries: map[string]config.RegistryMiddlewareConfig{
			"npm": {
				Validation: []config.Middleware{{Type: "cve-check", Params: mwYAML("mode: warn")}},
				Retrieval:  []config.Middleware{{Type: "local-disk-cache", Params: mwYAML("path: /tmp/cache")}},
			},
		},
	}
}

func TestProjectStorageRoundTrip(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	want := sampleConfig("acme")
	if err := st.Put(ctx, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.Get(ctx, "acme")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Key != "acme" {
		t.Errorf("key = %q, want acme", got.Key)
	}
	wantYAML, _ := yaml.Marshal(want.Registries)
	gotYAML, _ := yaml.Marshal(got.Registries)
	if string(gotYAML) != string(wantYAML) {
		t.Errorf("registries mismatch:\n got: %s\nwant: %s", gotYAML, wantYAML)
	}
}

func TestProjectStorageGetMissing(t *testing.T) {
	st, _ := openTestStore(t)
	_, err := st.Get(context.Background(), "nope")
	if err != project.ErrProjectNotFound {
		t.Fatalf("err = %v want ErrProjectNotFound", err)
	}
}

func TestProjectStorageUpsert(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	first := sampleConfig("lodash")
	rc := first.Registries["npm"]
	rc.Validation = []config.Middleware{{Type: "cve-check", Params: mwYAML("mode: deny")}}
	first.Registries["npm"] = rc
	if err := st.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := sampleConfig("lodash")
	if err := st.Put(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "lodash")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var pr map[string]string
	if err := got.Registries["npm"].Validation[0].Params.Decode(&pr); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if pr["mode"] != "warn" {
		t.Errorf("mode = %q, want warn (latest upsert must win)", pr["mode"])
	}
}

func TestProjectStorageListSorted(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	if err := st.Put(ctx, sampleConfig("zebra")); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, sampleConfig("alpha")); err != nil {
		t.Fatal(err)
	}
	got, err := st.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Key != "alpha" || got[1].Key != "zebra" {
		t.Errorf("list order = [%q %q], want [alpha zebra]", got[0].Key, got[1].Key)
	}
}

func TestProjectStorageDelete(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	if err := st.Put(ctx, sampleConfig("temp")); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "temp"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.Get(ctx, "temp"); err != project.ErrProjectNotFound {
		t.Fatalf("get after delete: err = %v want ErrProjectNotFound", err)
	}
	// Deleting a missing key is not an error.
	if err := st.Delete(ctx, "temp"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}
