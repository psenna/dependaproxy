// Package stripscripts implements a mutation middleware that strips npm install
// scripts (preinstall/install/postinstall) from package/package.json on every
// serve, repacking the tarball deterministically. It is best-effort: every error
// path returns nil and leaves ctx.Tarball.Bytes unchanged — a mutation must
// never fail the serve. It is npm-only; a config entry on another registry
// fails fast at BuildMutation ("unknown middleware type").
package stripscripts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/psenna/dependaproxy/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// installScriptKeys are the npm lifecycle scripts stripped from package.json.
var installScriptKeys = []string{"preinstall", "install", "postinstall"}

// Archive scan limits (zip-bomb defence) mirror malware's caps: a tarball with
// more entries than maxEntries or a single entry larger than maxEntryBytes is
// left unchanged (no-op) rather than repacked.
const (
	maxEntries    = 100_000
	maxEntryBytes = 256 << 20
)

var errTooManyEntries = errors.New("stripscripts: archive exceeds entry limit")

// Middleware strips npm install scripts on PostFetch.
type Middleware struct{}

// Name returns the config type string.
func (Middleware) Name() string { return "strip-install-scripts" }

// PreFetch is a no-op: nothing to do before fetch.
func (Middleware) PreFetch(*pipeline.PipelineContext) error { return nil }

// PostFetch strips preinstall/install/postinstall from package/package.json and
// repacks the tarball deterministically. Best-effort: every error path returns
// nil and leaves ctx.Tarball.Bytes unchanged; it never fails the serve.
func (Middleware) PostFetch(ctx *pipeline.PipelineContext) error {
	// TODO: re-tarring on every serve adds CPU; follow-up to cache mutated bytes
	// (keyed by upstream sha256 + mutator version).
	if ctx.Tarball == nil || len(ctx.Tarball.Bytes) == 0 || ctx.Registry != "npm" {
		return nil
	}
	entries, err := readTarGz(ctx.Tarball.Bytes)
	if err != nil {
		return nil // invalid gzip/tar (or zip-bomb): serve unchanged
	}
	idx := -1
	for i, e := range entries {
		if e.name == "package/package.json" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil // no package.json: nothing to strip
	}
	var pkg map[string]any
	if err := json.Unmarshal(entries[idx].data, &pkg); err != nil {
		return nil // unparsable package.json: serve unchanged
	}
	scripts, ok := pkg["scripts"].(map[string]any)
	if !ok {
		return nil // no scripts object: nothing to strip
	}
	stripped := false
	for _, key := range installScriptKeys {
		if _, exists := scripts[key]; exists {
			delete(scripts, key)
			stripped = true
		}
	}
	if !stripped {
		return nil // no install scripts present: avoid pointless re-tar
	}
	// Re-encode with json.Marshal: map keys are sorted lexicographically, so the
	// output is deterministic. The scripts object is kept even if empty (all
	// scripts were install scripts) — structure is preserved.
	newData, err := json.Marshal(pkg)
	if err != nil {
		return nil
	}
	entries[idx].data = newData
	entries[idx].size = int64(len(newData))
	repacked, err := repackTarGz(entries)
	if err != nil {
		return nil
	}
	ctx.Tarball.Bytes = repacked
	return nil
}

// tarEntry is one archive entry preserved for deterministic repacking. Only the
// header fields listed here are carried over; the repacked archive is rebuilt
// from these in original order.
type tarEntry struct {
	name     string
	mode     int64
	typeflag byte
	modTime  time.Time
	uname    string
	gname    string
	size     int64
	data     []byte
}

// readTarGz gunzips data and walks the tar, collecting every header+body in
// order. Entry-count / entry-size limits mirror malware's zip-bomb caps.
func readTarGz(data []byte) ([]tarEntry, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	tr := tar.NewReader(zr)
	var entries []tarEntry
	for n := 1; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if n > maxEntries {
			return nil, errTooManyEntries
		}
		e := tarEntry{
			name:     hdr.Name,
			mode:     hdr.Mode,
			typeflag: hdr.Typeflag,
			modTime:  hdr.ModTime,
			uname:    hdr.Uname,
			gname:    hdr.Gname,
			size:     hdr.Size,
		}
		if hdr.Size > 0 {
			if hdr.Size > maxEntryBytes {
				return nil, errTooManyEntries
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
			if err != nil {
				return nil, err
			}
			if int64(len(data)) != hdr.Size {
				return nil, io.ErrUnexpectedEOF // truncated entry: refuse to repack
			}
			e.data = data
		}
		entries = append(entries, e)
	}
}

// repackTarGz writes the entries back into a deterministic gzipped tar,
// preserving original entry order and each header's Name/Mode/Typeflag/ModTime/
// Uname/Gname (Size updated for the modified entry).
func repackTarGz(entries []tarEntry) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	// CRITICAL for determinism: without this the gzip header stamps the current
	// time and host OS into the output, so identical inputs would differ.
	// (Header is embedded in gzip.Writer, so these are the gzip header fields.)
	zw.ModTime = time.Unix(0, 0)
	zw.OS = 255
	zw.Name = ""
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Typeflag: e.typeflag,
			ModTime:  e.modTime,
			Uname:    e.uname,
			Gname:    e.gname,
			Size:     e.size,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if e.size > 0 {
			if _, err := tw.Write(e.data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Factory builds the Middleware. Registered by the npm adapter as
// "strip-install-scripts".
var Factory pipeline.MutationFactory = func(_ yaml.Node) (pipeline.MutationMiddleware, error) {
	return Middleware{}, nil
}
