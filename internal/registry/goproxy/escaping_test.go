package goproxy

import (
	"strings"
	"testing"
)

func TestEscapeRoundTrip(t *testing.T) {
	cases := []string{
		"github.com/Azure/azure-sdk-for-go",
		"example.com/lower",
		"golang.org/x/mod",
	}
	for _, in := range cases {
		esc, err := escapePath(in)
		if err != nil {
			t.Fatalf("escape %q: %v", in, err)
		}
		out, err := unescapePath(esc)
		if err != nil {
			t.Fatalf("unescape %q: %v", esc, err)
		}
		if out != in {
			t.Errorf("round trip %q -> %q -> %q", in, esc, out)
		}
	}
	esc, _ := escapePath("github.com/Azure/azure-sdk-for-go")
	if esc != "github.com/!azure/azure-sdk-for-go" {
		t.Errorf("escaped = %q", esc)
	}
	if !strings.Contains(esc, "!") {
		t.Errorf("escaped path %q should contain an escape", esc)
	}
}

func TestUnescapeInvalid(t *testing.T) {
	// An uppercase letter without a "!" escape is not a valid escaped path;
	// "!<upper>" is also an invalid escape sequence.
	for _, esc := range []string{"example.com/Azure", "example.com/!Z", "example.com/!9"} {
		if _, err := unescapePath(esc); err == nil {
			t.Errorf("unescape %q: want error", esc)
		}
	}
}
