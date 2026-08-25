// Package localcache implements the shared, registry-agnostic write-through
// artifact cache for validated artifacts. It sits before the upstream-registry
// middleware in the decorator chain: on a hit it serves from the cache backend;
// on a miss it calls next and write-through stores the result.
//
// The cache key is (registry, name, version, artifactID) read from the pipeline
// context — npm uses artifactID="" (name+version), pypi uses the filename,
// maven uses "classifier:type". The key is a platform-independent relative path
// (<registry>/<name...>/<version>.bin or .../<artifactID>.bin) that a CacheBackend
// maps to its storage (a file under a base dir for DiskBackend, an object key
// for an S3 backend).
package localcache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// CacheBackend stores and retrieves validated artifact bytes by cache key. A
// miss is reported with os.ErrNotExist. Implementations must be safe for
// concurrent use. The context is the request context (or the middleware's
// shutdown context) so backends can honour cancellation and deadlines.
type CacheBackend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
}

// DiskBackend stores artifacts under a base directory on the local filesystem.
type DiskBackend struct {
	base string
}

// NewDisk returns a DiskBackend rooted at base.
func NewDisk(base string) *DiskBackend { return &DiskBackend{base: base} }

// Get reads the artifact at base/key.
func (b *DiskBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx
	return os.ReadFile(filepath.Join(b.base, key)) //nolint:gosec // G304: key is sanitized via cacheKey
}

// Put atomically writes the artifact at base/key (temp file + rename).
func (b *DiskBackend) Put(ctx context.Context, key string, data []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx
	path := filepath.Join(b.base, key)
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

// Delete removes the artifact at base/key; a missing file is not an error.
func (b *DiskBackend) Delete(ctx context.Context, key string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx
	err := os.Remove(filepath.Join(b.base, key))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Middleware is a write-through cache for artifacts over any CacheBackend.
type Middleware struct {
	name    string
	backend CacheBackend
	next    pipeline.RetrievalMiddleware
	locks   keyLocks
}

// New returns a local-disk-cache middleware (DiskBackend rooted at base)
// wrapping next. Kept for backwards compatibility; prefer NewBackend when
// wrapping a non-disk backend.
func New(base string, next pipeline.RetrievalMiddleware) *Middleware {
	return NewBackend(NewDisk(base), next)
}

// NewBackend returns a cache middleware over an arbitrary CacheBackend,
// wrapping next.
func NewBackend(backend CacheBackend, next pipeline.RetrievalMiddleware) *Middleware {
	return newMiddleware("local-disk-cache", backend, next)
}

// NewNamedBackend is NewBackend with a custom middleware name (e.g. "s3-cache"
// when the backend is object storage).
func NewNamedBackend(name string, backend CacheBackend, next pipeline.RetrievalMiddleware) *Middleware {
	return newMiddleware(name, backend, next)
}

func newMiddleware(name string, backend CacheBackend, next pipeline.RetrievalMiddleware) *Middleware {
	return &Middleware{name: name, backend: backend, next: next, locks: keyLocks{locks: map[string]*sync.Mutex{}}}
}

// Name returns the config type string.
func (m *Middleware) Name() string { return m.name }

// Fetch serves a cached artifact on a hit; on a miss it calls next and
// write-through caches the result. A per-key mutex serializes concurrent
// requests for the same key so the upstream is fetched once.
func (m *Middleware) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	key, err := cacheKey(ctx.Registry, ctx.PkgName, ctx.Version, ctx.ArtifactID)
	if err != nil {
		return false, err
	}
	lk := m.locks.lock(key)
	lk.Lock()
	defer lk.Unlock()

	if data, rerr := m.backend.Get(ctx.Ctx, key); rerr == nil {
		ctx.Tarball = &pipeline.Tarball{Bytes: data}
		return true, nil
	} else if !os.IsNotExist(rerr) {
		// Unreadable cached entry (e.g. corrupt disk file): drop it, treat as miss.
		_ = m.backend.Delete(ctx.Ctx, key)
	}

	if m.next == nil {
		return false, pipeline.ErrNoResolver
	}
	hit, err := m.next.Fetch(ctx)
	if err != nil || !hit {
		return hit, err
	}
	if ctx.Tarball != nil {
		_ = m.backend.Put(ctx.Ctx, key, ctx.Tarball.Bytes)
	}
	return true, nil
}

// Evict removes the cached artifact for the key (used by the server when a
// cached artifact fails integrity verification). A missing entry is not an error.
func (m *Middleware) Evict(ctx *pipeline.PipelineContext) error {
	key, err := cacheKey(ctx.Registry, ctx.PkgName, ctx.Version, ctx.ArtifactID)
	if err != nil {
		return err
	}
	return m.backend.Delete(ctx.Ctx, key)
}

// cacheKey derives the cache key — a relative, platform-independent path — from
// the pipeline identity:
//   - artifactID == "": <registry>/<name...>/<version>.bin
//   - artifactID != "": <registry>/<name...>/<version>/<artifactID>.bin
//
// name may contain "/" (npm scoped names, maven group paths); each segment is
// validated. Path traversal segments are rejected.
func cacheKey(registry, name, version, artifactID string) (string, error) {
	regSeg, err := sanitize(registry, "registry")
	if err != nil {
		return "", err
	}
	nameParts := strings.Split(name, "/")
	segs := append([]string{regSeg}, nameParts...)
	for _, seg := range segs {
		if !validSeg(seg) {
			return "", fmt.Errorf("localcache: invalid path segment %q", seg)
		}
	}
	if !validSeg(version) {
		return "", fmt.Errorf("localcache: invalid version %q", version)
	}
	if artifactID == "" {
		return filepath.Join(append(segs, version+".bin")...), nil
	}
	if !validSeg(artifactID) {
		return "", fmt.Errorf("localcache: invalid artifactID %q", artifactID)
	}
	return filepath.Join(append(segs, version, artifactID+".bin")...), nil
}

func validSeg(s string) bool { return s != "" && s != "." && s != ".." && !strings.Contains(s, "/") }

func sanitize(s, kind string) (string, error) {
	if !validSeg(s) {
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

// Factory builds the middleware from its raw params node. Registered by each
// adapter under "local-disk-cache". Every call takes path from its own
// params — fine for a static, operator-only config.
var Factory pipeline.RetrievalFactory = func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("local-disk-cache: decode params: %w", err)
		}
	}
	return New(pr.Path, next), nil
}

// FactoryFixedPath returns a RetrievalFactory that always roots the cache at
// path, ignoring whatever `path` a caller's own params specify. Adapters use
// this to register "local-disk-cache" once operator config has pinned the
// path, so per-project admin-API overrides (H4) cannot redirect cache writes
// to an arbitrary directory the proxy process can create/write.
func FactoryFixedPath(path string) pipeline.RetrievalFactory {
	return func(_ yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
		return New(path, next), nil
	}
}
