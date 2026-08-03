// Package goproxy is the Go module proxy registry adapter: GOPROXY protocol
// routing, upstream client, and module path escaping. It implements the
// adapter.Adapter contract and is mounted at its configured prefix (e.g.
// /goproxy). v1 is pass-through only — storage/trust flow lands in a later
// issue.
package goproxy

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned when a module or version does not exist upstream.
var ErrNotFound = errors.New("goproxy: not found")

// Info is one entry in a GOPROXY @latest / .info response.
type Info struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// RegistryClient fetches Go module proxy protocol metadata and archives from
// upstream.
type RegistryClient interface {
	FetchList(ctx context.Context, module string) ([]string, error)
	FetchInfo(ctx context.Context, module, version string) (*Info, error)
	FetchMod(ctx context.Context, module, version string) ([]byte, error)
	FetchZip(ctx context.Context, module, version string) (io.ReadCloser, int64, error)
	FetchLatest(ctx context.Context, module string) (*Info, error)
}
