package project

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// TrackerConfig controls the dependency tracker's flush behavior.
type TrackerConfig struct {
	FlushInterval time.Duration
	BatchSize     int
	// DropInterval is the interval for periodic dropped-record summary logging.
	// <= 0 disables the summary ticker.
	DropInterval time.Duration
}

// DependencyTracker receives dependency download records to persist
// asynchronously. *Tracker implements it.
type DependencyTracker interface {
	Track(rec DependencyRecord)
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

// Tracker buffers dependency download records and flushes them to the store in
// batches. Track is non-blocking: a full buffer drops the record (counted)
// rather than stalling a request. Dropped records are surfaced for operational
// visibility: the first drop after a clean interval logs a warning, dropped
// counts are summarized on the configured DropInterval, and Dropped reports the
// running total. The flusher goroutine is owned by Start/Shutdown and always
// drains buffered records on Shutdown.
type Tracker struct {
	store              DependencyStore
	cfg                TrackerConfig
	buf                chan DependencyRecord
	flush              chan struct{}
	done               chan struct{}
	closed             atomic.Bool
	dropped            atomic.Int64
	droppedSinceReport atomic.Int64
	log                *slog.Logger
}

// NewTracker returns a Tracker with a buffer sized for the batch. A zero/negative
// BatchSize defaults to 100.
func NewTracker(store DependencyStore, cfg TrackerConfig, log *slog.Logger) *Tracker {
	batch := cfg.BatchSize
	if batch <= 0 {
		batch = 100
	}
	cap := 2 * batch
	if cap < 1024 {
		cap = 1024
	}
	return &Tracker{
		store: store,
		cfg:   TrackerConfig{FlushInterval: cfg.FlushInterval, BatchSize: batch, DropInterval: cfg.DropInterval},
		buf:   make(chan DependencyRecord, cap),
		flush: make(chan struct{}, 1),
		done:  make(chan struct{}),
		log:   log,
	}
}

// Start spawns the flusher goroutine. The goroutine's lifetime is bounded by
// Shutdown (which closes t.buf), not by ctx, so an application cancellation does
// not pre-empt the drain. ctx is intentionally unused.
func (t *Tracker) Start(_ context.Context) error {
	go t.flusher()
	return nil
}

// flusher consumes buffered records, flushing in batches on the configured
// interval, on an explicit Flush, on a full batch, and once on shutdown.
func (t *Tracker) flusher() {
	var tickerC <-chan time.Time
	if t.cfg.FlushInterval > 0 {
		ticker := time.NewTicker(t.cfg.FlushInterval)
		defer ticker.Stop()
		tickerC = ticker.C
	}
	var dropC <-chan time.Time
	if t.cfg.DropInterval > 0 {
		dropTicker := time.NewTicker(t.cfg.DropInterval)
		defer dropTicker.Stop()
		dropC = dropTicker.C
	}
	var batch []DependencyRecord
	flush := func() {
		if len(batch) == 0 {
			return
		}
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := t.store.UpsertBatch(flushCtx, batch); err != nil {
			t.recordDrops(len(batch))
			if t.log != nil {
				t.log.Error("dependency tracker flush", "records", len(batch), "err", err)
			}
		}
	}
	// drain deterministically covers every record already buffered on an explicit
	// Flush: consume the channel non-blocking (flushing any full sub-batches),
	// then flush the remainder.
	drain := func() {
		for {
			select {
			case rec, ok := <-t.buf:
				if !ok {
					return
				}
				batch = append(batch, rec)
				if len(batch) >= t.cfg.BatchSize {
					flush()
					batch = nil
				}
			default:
				flush()
				batch = nil
				return
			}
		}
	}
	for {
		select {
		case <-tickerC:
			flush()
			batch = nil
		case <-dropC:
			total := t.dropped.Load()
			since := t.droppedSinceReport.Swap(0)
			if since > 0 && t.log != nil {
				t.log.Warn("dependency tracker drops since last report", "dropped_since_report", since, "dropped_total", total)
			}
		case <-t.flush:
			drain()
		case rec, ok := <-t.buf:
			if !ok {
				flush()
				close(t.done)
				return
			}
			batch = append(batch, rec)
			if len(batch) >= t.cfg.BatchSize {
				flush()
				batch = nil
			}
		}
	}
}

// recordDrops accounts n dropped records and logs a one-time warning when drops
// begin after a clean interval. after == n only when the previous
// droppedSinceReport value was 0, so exactly one caller observes the
// 0->positive transition (race-free via atomicity).
func (t *Tracker) recordDrops(n int) {
	if n <= 0 {
		return
	}
	t.dropped.Add(int64(n))
	if after := t.droppedSinceReport.Add(int64(n)); after == int64(n) && t.log != nil {
		t.log.Warn("dependency tracker dropping records", "dropped", n, "dropped_total", t.dropped.Load())
	}
}

// Track enqueues a record for async persistence. It never blocks: a full buffer
// drops the record, which is counted and surfaced (first-drop warning and the
// periodic summary) and exposed via Dropped. After Shutdown, Track is a no-op.
//
// The closed.Load() guard is a fast path, not a hard guarantee: Shutdown may CAS
// closed=true and close t.buf in the window between that check and the send
// below, which would panic on a send to a closed channel. Recover converts
// that rare shutdown-concurrent race into a dropped record (counted), keeping
// the non-blocking contract. The default branch keeps the common full-buffer
// path panic-free without entering the deferred recover.
func (t *Tracker) Track(rec DependencyRecord) {
	if t.closed.Load() {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			t.recordDrops(1)
		}
	}()
	select {
	case t.buf <- rec:
	default:
		t.recordDrops(1)
	}
}

// Dropped returns the monotonic total of records dropped (full buffer, failed
// flush, or the shutdown-concurrent race) since the tracker started.
func (t *Tracker) Dropped() int64 { return t.dropped.Load() }

// Flush requests the flusher to emit any buffered records immediately. It is a
// test hook and never blocks.
func (t *Tracker) Flush() {
	select {
	case t.flush <- struct{}{}:
	default:
	}
}

// Shutdown closes the buffer, waits for the flusher to drain remaining records
// (final flush) and exit, or returns early if ctx expires.
func (t *Tracker) Shutdown(ctx context.Context) error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(t.buf)
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		if t.log != nil {
			t.log.Warn("dependency tracker shutdown timed out", "err", ctx.Err())
		}
		return ctx.Err()
	}
}
