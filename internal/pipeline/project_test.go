package pipeline

import (
	"strings"
	"testing"
)

// longKey returns a valid-charset project key of exactly n bytes, for testing
// the length bound in projectKeyRe.
func longKey(n int) string { return strings.Repeat("a", n) }

// TestParseProjectPath covers the project-scoping rules for registry-relative
// paths:
//   - A path is project-scoped iff, after one leading "/", segs[0] == "p" and
//     segs[1] is a non-empty key that is not "-".
//   - Otherwise the path passes through untouched with key "".
//   - When scoped, exactly "p/<key>/" is removed (leading slash preserved), so
//     "/p/myproj" -> "/" (downstream 404s on the empty remainder).
func TestParseProjectPath(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantRemaining  string
		wantProjectKey string
	}{
		{name: "default pkg", path: "/lodash", wantRemaining: "/lodash", wantProjectKey: ""},
		{name: "project scoped", path: "/p/myproj/lodash", wantRemaining: "/lodash", wantProjectKey: "myproj"},
		// Package "p" tarball: key "-" is reserved (npm's own "-" pseudo-package
		// is a registry control path) and must NOT be treated as a project key.
		{name: "package p tarball key dash", path: "/p/-/lodash-1.0.0.tgz", wantRemaining: "/p/-/lodash-1.0.0.tgz", wantProjectKey: ""},
		// Scoped npm package: segs[0] == "@scope", not "p".
		{name: "scoped pkg", path: "/@scope/pkg", wantRemaining: "/@scope/pkg", wantProjectKey: ""},
		// Empty key is rejected; the path passes through unchanged.
		{name: "empty key", path: "/p//lodash", wantRemaining: "/p//lodash", wantProjectKey: ""},
		{name: "trailing slash empty key", path: "/p/", wantRemaining: "/p/", wantProjectKey: ""},
		// Bare "/p" has no key segment at all.
		{name: "bare p", path: "/p", wantRemaining: "/p", wantProjectKey: ""},
		{name: "root", path: "/", wantRemaining: "/", wantProjectKey: ""},
		{name: "empty", path: "", wantRemaining: "", wantProjectKey: ""},
		// Edge: nothing follows "p/<key>/"; the remainder is "/", which the
		// downstream routes 404. The key is still captured.
		{name: "project root", path: "/p/myproj", wantRemaining: "/", wantProjectKey: "myproj"},
		{name: "project root trailing slash", path: "/p/myproj/", wantRemaining: "/", wantProjectKey: "myproj"},
		// PyPI index under a project.
		{name: "pypi index", path: "/p/myproj/simple/testpkg/", wantRemaining: "/simple/testpkg/", wantProjectKey: "myproj"},
		// PyPI file under a project.
		{name: "pypi file", path: "/p/myproj/files/t/1.0.0/x.whl", wantRemaining: "/files/t/1.0.0/x.whl", wantProjectKey: "myproj"},
		// Default (non-project) PyPI paths pass through untouched.
		{name: "default pypi index", path: "/simple/testpkg/", wantRemaining: "/simple/testpkg/", wantProjectKey: ""},
		{name: "default pypi file", path: "/files/t/1.0.0/x.whl", wantRemaining: "/files/t/1.0.0/x.whl", wantProjectKey: ""},
		// H5: a key outside the admin API's accepted charset can never
		// correspond to a real project, so it must not be treated as a project
		// scope at all -- it falls through to the default path instead of
		// reaching the resolver (and its cache) as a garbage key.
		{name: "key with disallowed characters", path: "/p/my@proj/lodash", wantRemaining: "/p/my@proj/lodash", wantProjectKey: ""},
		{name: "key with space", path: "/p/my proj/lodash", wantRemaining: "/p/my proj/lodash", wantProjectKey: ""},
		{name: "key with percent character", path: "/p/a%2Fb/lodash", wantRemaining: "/p/a%2Fb/lodash", wantProjectKey: ""},
		// H5: a key longer than the admin API would ever accept is rejected the
		// same way -- it can never correspond to a real project either.
		{name: "key over max length", path: "/p/" + longKey(129) + "/lodash", wantRemaining: "/p/" + longKey(129) + "/lodash", wantProjectKey: ""},
		{name: "key at max length", path: "/p/" + longKey(128) + "/lodash", wantRemaining: "/lodash", wantProjectKey: longKey(128)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRemaining, gotKey := ParseProjectPath(tt.path)
			if gotRemaining != tt.wantRemaining {
				t.Errorf("ParseProjectPath(%q) remaining = %q, want %q", tt.path, gotRemaining, tt.wantRemaining)
			}
			if gotKey != tt.wantProjectKey {
				t.Errorf("ParseProjectPath(%q) key = %q, want %q", tt.path, gotKey, tt.wantProjectKey)
			}
		})
	}
}

// TestValidProjectKey covers ValidProjectKey directly (H5): the same rule
// ParseProjectPath and the admin API both defer to.
func TestValidProjectKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"myproj", true},
		{"my-proj_1.0", true},
		{longKey(128), true},  // exactly at the cap
		{longKey(129), false}, // one over the cap
		{"", false},           // empty
		{"-", false},          // reserved sentinel
		{"my proj", false},    // space
		{"my/proj", false},    // slash (can't occur as a single path segment anyway, but reject defensively)
		{"my%2Fproj", false},  // percent
		{"проект", false},     // non-ASCII
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := ValidProjectKey(tt.key); got != tt.want {
				t.Errorf("ValidProjectKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}
