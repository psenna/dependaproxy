package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

const helloHex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

func TestSha256HexHello(t *testing.T) {
	got, n, err := Sha256Hex(strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != helloHex {
		t.Errorf("got %q want %q", got, helloHex)
	}
	if n != 5 {
		t.Errorf("bytes = %d want 5", n)
	}
}

func TestSha256HexEmpty(t *testing.T) {
	got, _, err := Sha256Hex(strings.NewReader(""))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty hash = %q", got)
	}
}

// TestSha256HexStreamsLarge verifies streaming of a multi-MiB reader without
// buffering the whole thing in memory (correctness over a size that would not
// fit in a typical copy buffer).
func TestSha256HexStreamsLarge(t *testing.T) {
	payload := bytes.Repeat([]byte("dependaproxy-streaming-test-"), 200_000) // ~6 MiB
	want := sha256.Sum256(payload)

	got, n, err := Sha256Hex(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != hex.EncodeToString(want[:]) {
		t.Errorf("hash mismatch")
	}
	if n != int64(len(payload)) {
		t.Errorf("bytes = %d want %d", n, len(payload))
	}
}

func TestVerifyHexMatch(t *testing.T) {
	ok, n, err := VerifyHex(helloHex, strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Error("want ok=true for matching hash")
	}
	if n != 5 {
		t.Errorf("bytes = %d want 5", n)
	}
}

func TestVerifyHexMismatch(t *testing.T) {
	ok, _, err := VerifyHex(helloHex, strings.NewReader("world"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Error("want ok=false for mismatched hash")
	}
}

func TestVerifyHexLengthMismatch(t *testing.T) {
	ok, _, err := VerifyHex("deadbeef", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Error("want ok=false for length-mismatched expected hash")
	}
}

func TestSha256HexReaderError(t *testing.T) {
	_, _, err := Sha256Hex(errReader{})
	if err == nil {
		t.Fatal("want error from failing reader")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }
