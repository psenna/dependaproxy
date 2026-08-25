package npm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/config"
	"github.com/psenna/dependaproxy/internal/denylist"
	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/middleware/mutation"
	"github.com/psenna/dependaproxy/internal/middleware/retrieval/localcache"
	"github.com/psenna/dependaproxy/internal/pipeline"
	"github.com/psenna/dependaproxy/internal/project"
)

// fakeDenyStore is an in-memory denylist.Store seeded with denials and counting
// Record calls. Lookup matches the exact (registry, name, version, sha256,
// projectKey) scope, mirroring the PostgresStore's strict per-scope matching.
type fakeDenyStore struct {
	mu      sync.Mutex
	denials map[string]string // scopeKey -> reason
	records int
}

func newFakeDenyStore() *fakeDenyStore {
	return &fakeDenyStore{denials: map[string]string{}}
}

func denyKey(registry, name, version, sha256, projectKey string) string {
	return registry + "|" + name + "|" + version + "|" + sha256 + "|" + projectKey
}

func (f *fakeDenyStore) seed(registry, name, version, sha256, projectKey, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denials[denyKey(registry, name, version, sha256, projectKey)] = reason
}

func (f *fakeDenyStore) recordCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records
}

func (f *fakeDenyStore) Lookup(_ context.Context, registry, name, version, sha256, projectKey string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reason, ok := f.denials[denyKey(registry, name, version, sha256, projectKey)]
	return reason, ok, nil
}

func (f *fakeDenyStore) Record(_ context.Context, _ denylist.Denial) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records++
	return nil
}

// newDenylistTestAdapter builds an npmAdapter mirroring newTestAdapterWithGlobal
// but with the deny-list wired in exactly as the real Factory does: the
// deny-list-check middleware is registered, a deny-list-check instance is
// built for the structural Prepend, and the resolver is given
// project.ValidationHooks{Prepend, Recorder}. The configured validation chain
// is min-publication-age (min_days 0), so any 403 on a 30-day-old package can
// only come from deny-list-check.
func newDenylistTestAdapter(t *testing.T, dir string, client RegistryClient, store Store, deny *fakeDenyStore, now func() time.Time) *npmAdapter {
	t.Helper()
	reg := pipeline.NewRegistry()
	reg.RegisterValidation("deny-list-check", denylist.Factory(deny))
	reg.RegisterValidation("min-publication-age", MinPubFactory)
	reg.RegisterRetrieval("local-disk-cache", localcache.Factory)
	reg.RegisterRetrieval("upstream-registry", UpstreamFactory(client))
	reg.RegisterMutation("noop", mutation.Factory)

	validation, err := reg.BuildValidation([]config.Middleware{{Type: "min-publication-age", Params: yamlNode("min_days: 0")}})
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := reg.BuildRetrieval([]config.Middleware{
		{Type: "local-disk-cache", Params: yamlNode("path: " + dir)},
		{Type: "upstream-registry"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mp, err := reg.BuildMutation(nil)
	if err != nil {
		t.Fatal(err)
	}
	mp.Chain = []pipeline.MutationMiddleware{mutation.NoOp{}}

	var cache pipeline.Evictor
	if e, ok := retrieval.Head.(pipeline.Evictor); ok {
		cache = e
	}
	global := &project.Resolved{Validation: validation, Retrieval: retrieval, Mutation: mp, Cache: cache}

	dlv, err := reg.BuildValidation([]config.Middleware{{Type: "deny-list-check"}})
	if err != nil {
		t.Fatal(err)
	}
	hooks := project.ValidationHooks{
		Prepend:   dlv.Chain[0],
		OnFailure: denylist.Recorder(deny, now),
	}
	resolver := project.NewResolver("npm", reg, fakeProjectStore{}, global, hooks)
	return &npmAdapter{
		prefix:   "/npm",
		storage:  store,
		client:   client,
		resolver: resolver,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:      now,
	}
}

// fetchTarballDirect GETs a tarball path (which may carry a /p/<key>/ project
// prefix) and returns the status code and body.
func fetchTarballDirect(t *testing.T, base, path string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(base + path) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

// TestDenylistCheckShortCircuits403 proves the deny-list-check runs FIRST: a
// previously-denied package is rejected with the stored reason before any
// downstream validation can fail-open or serve it.
func TestDenylistCheckShortCircuits403(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("EVIL-TARBALL")
	sha, _, err := hash.Sha256Hex(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}
	deny := newFakeDenyStore()
	deny.seed("npm", "evil-pkg", "1.0.0", sha, "", "blocked by policy for test")

	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	client := &rawClient{pack: pack, raw: raw, tarball: tarball}
	a := newDenylistTestAdapter(t, dir, client, newMemStore(), deny, func() time.Time { return time.Now().UTC() })
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "evil-pkg", "1.0.0")
	if code != 403 {
		t.Fatalf("code=%d want 403 (deny-list short-circuit)", code)
	}
	if !bytes.Contains(body, []byte("deny-list-check")) {
		t.Errorf("body = %q, want it to name deny-list-check", body)
	}
	if !bytes.Contains(body, []byte("blocked by policy for test")) {
		t.Errorf("body = %q, want the stored denial reason", body)
	}
}

// TestDenylistProjectScoping drives a project-scoped denial through the real
// request path: a projectless request is served, a project-scoped request for
// the same artifact is denied.
func TestDenylistProjectScoping(t *testing.T) {
	tarball := []byte("TARBALL")
	sha, _, err := hash.Sha256Hex(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}

	// Projectless request: the proj-a-scoped denial must NOT block it.
	{
		dir := t.TempDir()
		deny := newFakeDenyStore()
		deny.seed("npm", "testpkg", "1.0.0", sha, "proj-a", "project-scoped denial")
		pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
		client := &rawClient{pack: pack, raw: raw, tarball: tarball}
		a := newDenylistTestAdapter(t, dir, client, newMemStore(), deny, func() time.Time { return time.Now().UTC() })
		srv := newTestServer(t, a)

		code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
		if code != 200 || !bytes.Equal(body, tarball) {
			t.Fatalf("projectless: code=%d want 200 served", code)
		}
	}

	// Project-scoped request (fresh store/adapter so no trusted record): denied.
	{
		dir := t.TempDir()
		deny := newFakeDenyStore()
		deny.seed("npm", "testpkg", "1.0.0", sha, "proj-a", "project-scoped denial")
		pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
		client := &rawClient{pack: pack, raw: raw, tarball: tarball}
		a := newDenylistTestAdapter(t, dir, client, newMemStore(), deny, func() time.Time { return time.Now().UTC() })
		srv := newTestServer(t, a)

		code, body := fetchTarballDirect(t, srv.URL+"/npm", "/p/proj-a/testpkg/-/1.0.0")
		if code != 403 {
			t.Fatalf("project-scoped: code=%d want 403", code)
		}
		if !bytes.Contains(body, []byte("project-scoped denial")) {
			t.Errorf("body = %q, want the project-scoped stored reason", body)
		}
	}
}

// TestDenylistBlocksTrustedCacheHit is the regression test for the H2
// deny-list half: a trust-store hit must not bypass a denial recorded after
// the artifact was originally validated. Without serveTrusted re-running
// deny-list-check, this request would be served straight from the cache with
// no validation at all.
func TestDenylistBlocksTrustedCacheHit(t *testing.T) {
	dir := t.TempDir()
	tarball := []byte("TARBALL")
	sha, _, err := hash.Sha256Hex(bytes.NewReader(tarball))
	if err != nil {
		t.Fatal(err)
	}

	store := newMemStore()
	store.recs[k("", "testpkg", "1.0.0")] = Record{Name: "testpkg", Version: "1.0.0", ValidationHash: sha, ValidatedAt: time.Now().UTC()}

	deny := newFakeDenyStore()
	// Seeded as if the operator denylisted this exact sha256 *after* it was
	// originally validated and stored -- the scenario the trust store alone
	// cannot protect against.
	deny.seed("npm", "testpkg", "1.0.0", sha, "", "denied after validation")

	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), tarball)
	client := &rawClient{pack: pack, raw: raw, tarball: tarball}
	a := newDenylistTestAdapter(t, dir, client, store, deny, func() time.Time { return time.Now().UTC() })
	srv := newTestServer(t, a)

	code, body := fetchViaProxy(t, srv.URL+"/npm", "testpkg", "1.0.0")
	if code != 403 {
		t.Fatalf("code=%d want 403 (trusted cache hit must re-check deny-list)", code)
	}
	if !bytes.Contains(body, []byte("denied after validation")) {
		t.Errorf("body = %q, want the stored denial reason", body)
	}
}

// TestDenylistWiringStructural asserts the resolver applied the hooks: every
// Resolve (here the projectless default) yields a validation chain that starts
// with deny-list-check and carries a non-nil OnFailure recorder.
func TestDenylistWiringStructural(t *testing.T) {
	dir := t.TempDir()
	deny := newFakeDenyStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newDenylistTestAdapter(t, dir, client, newMemStore(), deny, func() time.Time { return time.Now().UTC() })

	rp, err := a.resolver.Resolve(context.Background(), "")
	if err != nil {
		t.Fatalf("resolve default: %v", err)
	}
	if len(rp.Validation.Chain) == 0 {
		t.Fatal("validation chain empty")
	}
	if got := rp.Validation.Chain[0].Name(); got != "deny-list-check" {
		t.Errorf("chain[0].Name() = %q, want %q", got, "deny-list-check")
	}
	if rp.Validation.OnFailure == nil {
		t.Error("OnFailure is nil, want the denylist recorder")
	}
}

// TestDenylistRecorderWired invokes the resolver's OnFailure hook with a real
// validation failure and asserts the recorder persists it to the deny store
// (a thin re-check that the wiring reaches the recorder, not a re-test of the
// recorder logic covered in internal/denylist/record_test.go).
func TestDenylistRecorderWired(t *testing.T) {
	dir := t.TempDir()
	deny := newFakeDenyStore()
	pack, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("TARBALL"))
	client := &rawClient{pack: pack, raw: raw, tarball: []byte("TARBALL")}
	a := newDenylistTestAdapter(t, dir, client, newMemStore(), deny, func() time.Time { return time.Now().UTC() })

	rp, err := a.resolver.Resolve(context.Background(), "")
	if err != nil {
		t.Fatalf("resolve default: %v", err)
	}
	if rp.Validation.OnFailure == nil {
		t.Fatal("OnFailure is nil, want the denylist recorder")
	}
	ctx := pipeline.NewPipelineContext(context.Background(), slog.New(slog.DiscardHandler), "npm", "testpkg", "1.0.0", "")
	ctx.Tarball = &pipeline.Tarball{Bytes: []byte("TARBALL")}
	rp.Validation.OnFailure(ctx, &pipeline.ValidationError{
		Middleware: "cve-check",
		Err:        errors.New("cve-check: testpkg@1.0.0 has a known CVE"),
	})
	if n := deny.recordCount(); n != 1 {
		t.Errorf("Record calls = %d, want 1 (resolver OnFailure must reach the recorder)", n)
	}
}
