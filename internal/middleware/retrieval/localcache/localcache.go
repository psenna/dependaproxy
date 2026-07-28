// Package localcache implements the v1 retrieval middleware that caches
// validated tarballs on local disk (write-through). It sits before the
// upstream-registry middleware in the decorator chain: on a hit it serves from
// disk; on a miss it calls next and atomically writes the result back.
package localcache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Middleware is a write-through local disk cache for tarballs.
type Middleware struct {
	base  string
	next  pipeline.RetrievalMiddleware
	locks keyLocks
}

// New returns a local-disk-cache middleware rooted at base, wrapping next.
func New(base string, next pipeline.RetrievalMiddleware) *Middleware {
	return &Middleware{base: base, next: next, locks: keyLocks{locks: map[string]*sync.Mutex{}}}
}

// Name returns the config type string.
func (*Middleware) Name() string { return "local-disk-cache" }

// Fetch serves a cached tarball on a hit; on a miss it calls next and
// write-through caches the result. A per-key mutex serializes concurrent
// requests for the same (registry,name,version) so the upstream is fetched once.
func (m *Middleware) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	path, err := cachePath(m.base, ctx.Registry, ctx.PkgName, ctx.Version)
	if err != nil {
		return false, err
	}
	lk := m.locks.lock(path)
	lk.Lock()
	defer lk.Unlock()

	if data, rerr := os.ReadFile(path); rerr == nil { //nolint:gosec // G304: path is sanitized via cachePath
		ctx.Tarball = &pipeline.Tarball{Bytes: data}
		return true, nil
	} else if !os.IsNotExist(rerr) {
		// Unreadable/odd file: drop it and fall through.
		_ = os.Remove(path)
	}

	if m.next == nil {
		return false, pipeline.ErrNoResolver
	}
	hit, err := m.next.Fetch(ctx)
	if err != nil || !hit {
		return hit, err
	}
	if ctx.Tarball != nil {
		// Cache write failure is non-fatal: the package is still served.
		_ = m.writeAtomic(path, ctx.Tarball.Bytes)
	}
	return true, nil
}

// Evict removes the cached tarball for the key (used by the server when a cached
// artifact fails integrity verification). A missing file is not an error.
func (m *Middleware) Evict(ctx *pipeline.PipelineContext) error {
	path, err := cachePath(m.base, ctx.Registry, ctx.PkgName, ctx.Version)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *Middleware) writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cache-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// cachePath builds a sanitized cache path: <base>/<registry>/<name...>/<version>.tgz.
// Scoped names (@org/pkg) become a directory tree. Path traversal segments are
// rejected.
func cachePath(base, registry, name, version string) (string, error) {
	regSeg, err := sanitize(registry, "registry")
	if err != nil {
		return "", err
	}
	nameParts := strings.Split(name, "/")
	segs := append([]string{base, regSeg}, nameParts...)
	segs = append(segs, version+".tgz")
	for i, seg := range segs {
		// base (i==0) is operator-provided; do not sanitize it.
		if i == 0 {
			continue
		}
		if seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, `/\`) {
			return "", fmt.Errorf("localcache: invalid path segment %q", seg)
		}
	}
	return filepath.Join(segs...), nil
}

func sanitize(s, kind string) (string, error) {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) {
		return "", fmt.Errorf("localcache: invalid %s %q", kind, s)
	}
	return s, nil
}

type keyLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyLocks) lock(key string) *sync.Mutex {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, ok := k.locks[key]
	if !ok {
		l = &sync.Mutex{}
		k.locks[key] = l
	}
	return l
}

type params struct {
	Path string `yaml:"path"`
}

// Factory builds the middleware from its raw params node. Registered by the
// server as "local-disk-cache".
var Factory pipeline.RetrievalFactory = func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("local-disk-cache: decode params: %w", err)
		}
	}
	return New(pr.Path, next), nil
}
