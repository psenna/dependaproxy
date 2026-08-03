package pypi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/psenna/dependaproxy/internal/hash"
	"github.com/psenna/dependaproxy/internal/project"
)

// fakeDependencyTracker records Tracked records; it never flushes to a DB.
type fakeDependencyTracker struct {
	mu      sync.Mutex
	records []project.DependencyRecord
}

func (f *fakeDependencyTracker) Track(rec project.DependencyRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
}
func (f *fakeDependencyTracker) Start(context.Context) error    { return nil }
func (f *fakeDependencyTracker) Shutdown(context.Context) error { return nil }

func (f *fakeDependencyTracker) all() []project.DependencyRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]project.DependencyRecord(nil), f.records...)
}

// newTestAdapterWithTracker is newTestAdapter plus a DependencyTracker; a nil
// tracker leaves the existing (untracked) behavior unchanged.
func newTestAdapterWithTracker(t *testing.T, prefix, dir string, minDays int, client RegistryClient, store Store, tracker project.DependencyTracker) *pypiAdapter {
	t.Helper()
	a := newTestAdapterWithGlobal(t, prefix, dir, minDays, client, store, nil)
	a.tracker = tracker
	return a
}

func TestPypiProjectDownloadTracked(t *testing.T) {
	dir := t.TempDir()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &captureClient{project: proj, raw: raw, file: []byte("WHEEL")}
	tracker := &fakeDependencyTracker{}
	a := newTestAdapterWithTracker(t, "/pypi", dir, 0, c, newMemStore(), tracker)
	srv := newTestServer(t, a)

	resp, err := http.Get(srv.URL + "/pypi/p/acme/files/testpkg/1.0.0/" + wheelFile) //nolint:gosec // G107: proxy URL under test
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "WHEEL" {
		t.Fatalf("file: code=%d body=%q want 200/WHEEL", resp.StatusCode, body)
	}

	recs := tracker.all()
	if len(recs) != 1 {
		t.Fatalf("tracked %d records, want 1", len(recs))
	}
	wantHash, _, _ := hash.Sha256Hex(bytes.NewReader([]byte("WHEEL")))
	got := recs[0]
	if got.ProjectKey != "acme" || got.Registry != "pypi" || got.Pkg != "testpkg" ||
		got.Version != "1.0.0" || got.ArtifactID != wheelFile || got.SHA256 != wantHash {
		t.Errorf("record = %+v", got)
	}
}

func TestPypiDefaultPathNotTracked(t *testing.T) {
	dir := t.TempDir()
	proj, raw := buildPack(time.Now().AddDate(0, 0, -30), []byte("WHEEL"))
	c := &captureClient{project: proj, raw: raw, file: []byte("WHEEL")}
	tracker := &fakeDependencyTracker{}
	a := newTestAdapterWithTracker(t, "/pypi", dir, 0, c, newMemStore(), tracker)
	srv := newTestServer(t, a)

	code, _ := fetchViaProxy(t, srv.URL+"/pypi", "testpkg")
	if code != http.StatusOK {
		t.Fatalf("default path: code=%d want 200", code)
	}
	if recs := tracker.all(); len(recs) != 0 {
		t.Fatalf("tracked %d records on default path, want 0 (ProjectKey==\"\" short-circuit)", len(recs))
	}
}
