// Package localcache implements the shared, registry-agnostic write-through
// local disk cache for validated artifacts. It sits before the
// upstream-registry middleware in the decorator chain: on a hit it serves from
// disk; on a miss it calls next and atomically writes the result back. The
// cache key is (registry, name, version, artifactID) read from the pipeline
// context — npm uses artifactID="" (name+version), pypi uses the filename,
// maven uses "classifier:type".
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

// Middleware is a write-through local disk cache for artifacts.
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

// Fetch serves a cached artifact on a hit; on a miss it calls next and
// write-through caches the result. A per-key mutex serializes concurrent
// requests for the same key so the upstream is fetched once.
func (m *Middleware) Fetch(ctx *pipeline.PipelineContext) (bool, error) {
	path, err := cachePath(m.base, ctx.Registry, ctx.PkgName, ctx.Version, ctx.ArtifactID)
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
		_ = m.writeAtomic(path, ctx.Tarball.Bytes)
	}
	return true, nil
}

// Evict removes the cached artifact for the key (used by the server when a
// cached artifact fails integrity verification). A missing file is not an error.
func (m *Middleware) Evict(ctx *pipeline.PipelineContext) error {
	path, err := cachePath(m.base, ctx.Registry, ctx.PkgName, ctx.Version, ctx.ArtifactID)
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

// cachePath builds a sanitized cache path:
//   - artifactID == "": <base>/<registry>/<name...>/<version>.bin
//   - artifactID != "": <base>/<registry>/<name...>/<version>/<artifactID>.bin
//
// name may contain "/" (npm scoped names, maven group paths); each segment is
// validated. Path traversal segments are rejected.
func cachePath(base, registry, name, version, artifactID string) (string, error) {
	regSeg, err := sanitize(registry, "registry")
	if err != nil {
		return "", err
	}
	nameParts := strings.Split(name, "/")
	segs := append([]string{base, regSeg}, nameParts...)
	for i, seg := range segs {
		if i == 0 { // base is operator-provided; do not sanitize it
			continue
		}
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
// adapter under "local-disk-cache".
var Factory pipeline.RetrievalFactory = func(p yaml.Node, next pipeline.RetrievalMiddleware) (pipeline.RetrievalMiddleware, error) {
	var pr params
	if !p.IsZero() {
		if err := p.Decode(&pr); err != nil {
			return nil, fmt.Errorf("local-disk-cache: decode params: %w", err)
		}
	}
	return New(pr.Path, next), nil
}
