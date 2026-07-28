// Package storage persists validated package records. The Storage interface
// keeps the backend swappable; v1 provides a PostgreSQL implementation.
package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Get when no validated record exists for the key.
var ErrNotFound = errors.New("storage: not found")

// PackageRecord is a validated package entry: the (name, version, registry)
// composite key, the sha256 trust-anchor hash, the validation timestamp, and
// free-form validation metadata as a JSON blob.
type PackageRecord struct {
	Name           string
	Version        string
	Registry       string
	ValidationHash string
	ValidatedAt    time.Time
	Metadata       []byte
}

// Storage persists and retrieves validated package records.
type Storage interface {
	// Get returns the record for the composite key, or ErrNotFound.
	Get(ctx context.Context, name, version, registry string) (PackageRecord, error)
	// Put upserts the record on the composite key (re-validation updates the
	// hash, timestamp, and metadata).
	Put(ctx context.Context, r PackageRecord) error
	// Close releases the backend. Idempotent.
	Close() error
}
