// Package hash provides streaming strong-hash helpers. The sha256 of a
// package's tarball bytes is DependaProxy's trust anchor: it is stored when a
// package is validated and recomputed (and compared in constant time) on every
// retrieval, so a mismatch (tampered cache, corrupted disk, upstream drift) is
// never served.
package hash

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

// Sha256Hex streams r through sha256 and returns the lowercase hex digest and
// the number of bytes read. It does not buffer the whole reader.
func Sha256Hex(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, fmt.Errorf("read for hashing: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// VerifyHex streams r, computes its sha256, and compares the hex digest to
// expected in constant time. Returns ok=true on a match. A length mismatch in
// expected yields ok=false (not an error). An error from reading is returned.
func VerifyHex(expected string, r io.Reader) (bool, int64, error) {
	got, n, err := Sha256Hex(r)
	if err != nil {
		return false, 0, err
	}
	if len(got) != len(expected) {
		return false, n, nil
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1, n, nil
}
