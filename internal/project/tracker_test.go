package project

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDependencyStore records the batches UpsertBatch receives. A non-nil err
// makes UpsertBatch fail (after the batch is recorded), so a flusher flush error
// can be simulated.
type fakeDependencyStore struct {
	mu      sync.Mutex
	batches [][]DependencyRecord
	upserts int
	err     error
}

func (f *fakeDependencyStore) UpsertBatch(_ context.Context, recs []DependencyRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]DependencyRecord(nil), recs...)
	f.batches = append(f.batches, cp)
	f.upserts++
	return f.err
}

func (f *fakeDependencyStore) List(context.Context, string, DependencyListFilters) ([]DependencyRecord, error) {
	return nil, nil
}

func (f *fakeDependencyStore) snapshot() [][]DependencyRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]DependencyRecord(nil), f.batches...)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// syncBuffer is a bytes.Buffer safe for concurrent write (from the tracker's
// goroutines) and read (from the test goroutine), so -race stays clean while
// polling the captured log output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogger returns a logger writing to a shared in-memory buffer, so tests
// can assert on the tracker's log output.
func captureLogger(t *testing.T) (*slog.Logger, *syncBuffer) {
	t.Helper()
	buf := &syncBuffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

func eventually(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}

func TestTrackerBatchThresholdFlush(t *testing.T) {
	store := &fakeDependencyStore{}
	tr := NewTracker(store, TrackerConfig{BatchSize: 3}, discardLogger())
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for i := 0; i < 3; i++ {
		tr.Track(DependencyRecord{Pkg: "pkg"})
	}
	eventually(t, time.Second, func() bool { return len(store.snapshot()) == 1 })
	got := store.snapshot()[0]
	if len(got) != 3 {
		t.Fatalf("batch len = %d, want 3", len(got))
	}
}

func TestTrackerTimeFlush(t *testing.T) {
	store := &fakeDependencyStore{}
	tr := NewTracker(store, TrackerConfig{BatchSize: 100, FlushInterval: 20 * time.Millisecond}, discardLogger())
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	tr.Track(DependencyRecord{Pkg: "pkg"})
	eventually(t, 200*time.Millisecond, func() bool { return len(store.snapshot()) == 1 })
	got := store.snapshot()[0]
	if len(got) != 1 {
		t.Fatalf("batch len = %d, want 1", len(got))
	}
}

func TestTrackerFlushHook(t *testing.T) {
	store := &fakeDependencyStore{}
	tr := NewTracker(store, TrackerConfig{BatchSize: 100}, discardLogger())
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	tr.Track(DependencyRecord{Pkg: "a"})
	tr.Track(DependencyRecord{Pkg: "b"})
	tr.Flush()
	eventually(t, time.Second, func() bool { return len(store.snapshot()) == 1 })
	got := store.snapshot()[0]
	if len(got) != 2 {
		t.Fatalf("batch len = %d, want 2", len(got))
	}
}

func TestTrackerDrainsOnShutdown(t *testing.T) {
	store := &fakeDependencyStore{}
	tr := NewTracker(store, TrackerConfig{BatchSize: 100}, discardLogger())
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		tr.Track(DependencyRecord{Pkg: "pkg"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if len(store.snapshot()) != 1 {
		t.Fatalf("batches = %d, want 1 (final flush on drain)", len(store.snapshot()))
	}
	if got := store.snapshot()[0]; len(got) != 5 {
		t.Fatalf("batch len = %d, want 5", len(got))
	}
}

func TestTrackerDropPolicy(t *testing.T) {
	// A hand-built tracker with a tiny buffer and NO flusher goroutine, so the
	// buffer stays full and every Track beyond the two slots must drop (non-
	// blocking, no panic).
	tr := &Tracker{
		cfg:   TrackerConfig{BatchSize: 100},
		buf:   make(chan DependencyRecord, 2),
		flush: make(chan struct{}, 1),
		done:  make(chan struct{}),
		log:   discardLogger(),
	}
	tr.Track(DependencyRecord{Pkg: "a"})
	tr.Track(DependencyRecord{Pkg: "b"})
	for i := 0; i < 50; i++ {
		tr.Track(DependencyRecord{Pkg: "flood"})
	}
	if got := tr.dropped.Load(); got < 50 {
		t.Fatalf("dropped = %d, want >= 50", got)
	}
	if got := tr.Dropped(); got < 50 {
		t.Fatalf("Dropped() = %d, want >= 50", got)
	}
	// Track after Shutdown (closed flag set) must be a no-op, never a panic.
	tr.closed.Store(true)
	tr.Track(DependencyRecord{Pkg: "after-close"})
}

func TestTrackerConcurrentTrackShutdown(t *testing.T) {
	// Track racing with Shutdown must never panic on a send to a closed
	// channel. The closed.Load() guard has a TOCTOU window; the recover in
	// Track converts that race into a dropped record (counted). This test
	// runs under -race to catch any regression.
	store := &fakeDependencyStore{}
	tr := NewTracker(store, TrackerConfig{BatchSize: 100}, discardLogger())
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tr.Track(DependencyRecord{Pkg: "race"})
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tr.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	wg.Wait()
}

func TestTrackerNonBlockingTrack(t *testing.T) {
	tr := &Tracker{
		cfg:   TrackerConfig{BatchSize: 100},
		buf:   make(chan DependencyRecord, 2),
		flush: make(chan struct{}, 1),
		done:  make(chan struct{}),
		log:   discardLogger(),
	}
	tr.Track(DependencyRecord{Pkg: "a"})
	tr.Track(DependencyRecord{Pkg: "b"})
	start := time.Now()
	for i := 0; i < 1000; i++ {
		tr.Track(DependencyRecord{Pkg: "flood"})
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("1000 Track calls took %s, want fast (non-blocking)", elapsed)
	}
	tr.closed.Store(true)
}

func TestTrackerFirstDropWarning(t *testing.T) {
	// A hand-built tracker with a tiny buffer and NO flusher goroutine: every
	// Track beyond the two slots drops on the full-buffer default path. The
	// first drop after a clean interval must log exactly one warning; the rest
	// stay silent.
	log, buf := captureLogger(t)
	tr := &Tracker{
		cfg:   TrackerConfig{BatchSize: 100},
		buf:   make(chan DependencyRecord, 2),
		flush: make(chan struct{}, 1),
		done:  make(chan struct{}),
		log:   log,
	}
	tr.Track(DependencyRecord{Pkg: "a"})
	tr.Track(DependencyRecord{Pkg: "b"})
	for i := 0; i < 50; i++ {
		tr.Track(DependencyRecord{Pkg: "flood"})
	}
	if got := buf.String(); !strings.Contains(got, "dependency tracker dropping records") {
		t.Fatalf("buffer = %q, want first-drop warning", got)
	}
	if got := strings.Count(buf.String(), "dependency tracker dropping records"); got != 1 {
		t.Fatalf("first-drop warning logged %d times, want exactly 1", got)
	}
	if got := tr.Dropped(); got < 50 {
		t.Fatalf("Dropped() = %d, want >= 50", got)
	}
}

func TestTrackerPeriodicDropSummary(t *testing.T) {
	// A store that always fails: the flusher's failed flush drops the whole
	// batch, and the periodic summary must report the drops since the last
	// report.
	store := &fakeDependencyStore{err: errors.New("boom")}
	log, buf := captureLogger(t)
	tr := NewTracker(store, TrackerConfig{BatchSize: 3, DropInterval: 10 * time.Millisecond}, log)
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	for i := 0; i < 3; i++ {
		tr.Track(DependencyRecord{Pkg: "pkg"})
	}
	eventually(t, time.Second, func() bool {
		s := buf.String()
		return strings.Contains(s, "dependency tracker dropping records") && strings.Contains(s, "drops since last report")
	})
	if got := buf.String(); !strings.Contains(got, "dropped_since_report=3") {
		t.Fatalf("buffer = %q, want dropped_since_report=3", got)
	}
	if got := tr.Dropped(); got != 3 {
		t.Fatalf("Dropped() = %d, want 3", got)
	}
}

func TestTrackerPeriodicSummaryNoDropsNoLog(t *testing.T) {
	// With no drops, the summary ticker must stay silent.
	store := &fakeDependencyStore{}
	log, buf := captureLogger(t)
	tr := NewTracker(store, TrackerConfig{BatchSize: 100, DropInterval: 20 * time.Millisecond}, log)
	if err := tr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tr.Shutdown(context.Background()) }()

	time.Sleep(60 * time.Millisecond)
	if got := buf.String(); got != "" {
		t.Fatalf("buffer = %q, want empty (no drops -> no logs)", got)
	}
}
