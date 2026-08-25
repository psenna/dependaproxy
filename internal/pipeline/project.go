package pipeline

import (
	"context"
	"regexp"
	"strings"
)

// projectKeyRe bounds a project key to the characters the admin API has
// always accepted, plus a length cap (the trailing {1,128}): a garbage key is
// otherwise an effectively-unbounded string (a valid path segment can run up
// to the server's MaxHeaderBytes) before it ever reaches the resolver cache.
var projectKeyRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// ValidProjectKey reports whether key is an acceptable project key: 1-128
// bytes drawn only from [a-zA-Z0-9._-], and not the reserved "-" sentinel
// (pipeline.ParseProjectPath treats a bare "-" segment as "no project scope",
// so it must never be usable as a real key either).
//
// Shared by ParseProjectPath (URL parsing, H5) and the admin API (project
// CRUD) so the two surfaces agree on exactly which strings are ever treated
// as a project scope -- a key the admin API would reject can't be smuggled in
// through a request URL to grow the resolver's per-key cache.
func ValidProjectKey(key string) bool {
	return key != "-" && projectKeyRe.MatchString(key)
}

// ParseProjectPath splits a registry-relative URL path into the project key
// (if any) and the remaining path the existing routes should consume.
//
// A path is project-scoped iff, after stripping one leading "/", its first
// segment is "p" and its second segment is a valid project key (see
// ValidProjectKey). Then it returns (remaining, key) where remaining is the
// path with exactly "p/<key>/" removed (leading slash preserved). Otherwise
// it returns (path, "") and the caller routes exactly as before -- including
// when the second segment is a syntactically-invalid key, which is treated as
// "no project scope" rather than an error, matching the existing "-" handling
// this replaces.
func ParseProjectPath(path string) (remaining, projectKey string) {
	s := strings.TrimPrefix(path, "/")
	segs := strings.Split(s, "/")
	if len(segs) < 2 || segs[0] != "p" {
		return path, ""
	}
	key := segs[1]
	if !ValidProjectKey(key) {
		return path, ""
	}
	remaining = "/" + strings.Join(segs[2:], "/")
	return remaining, key
}

type projectKeyCtxKey struct{}

// ContextWithProjectKey returns a context carrying the project key.
func ContextWithProjectKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, projectKeyCtxKey{}, key)
}

// ProjectKeyFromContext returns the project key carried in ctx, or "".
func ProjectKeyFromContext(ctx context.Context) string {
	if v, _ := ctx.Value(projectKeyCtxKey{}).(string); v != "" {
		return v
	}
	return ""
}
