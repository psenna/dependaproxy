package pipeline

import "testing"

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
