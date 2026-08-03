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
// rather than stalling a request. The flusher goroutine is owned by
// Start/Shutdown and always drains buffered records on Shutdown.
type Tracker struct {
	store   DependencyStore
	cfg     TrackerConfig
	buf     chan DependencyRecord
	flush   chan struct{}
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Int64
	log     *slog.Logger
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
		cfg:   TrackerConfig{FlushInterval: cfg.FlushInterval, BatchSize: batch},
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
	var batch []DependencyRecord
	flush := func() {
		if len(batch) == 0 {
			return
		}
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := t.store.UpsertBatch(flushCtx, batch); err != nil {
			t.dropped.Add(int64(len(batch)))
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

// Track enqueues a record for async persistence. It never blocks: a full buffer
// drops the record and increments the dropped counter. After Shutdown, Track is
// a no-op.
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
			t.dropped.Add(1)
		}
	}()
	select {
	case t.buf <- rec:
	default:
		t.dropped.Add(1)
	}
}

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
