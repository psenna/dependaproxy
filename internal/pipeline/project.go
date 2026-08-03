package pipeline

import (
	"context"
	"strings"
)

// ParseProjectPath splits a registry-relative URL path into the project key
// (if any) and the remaining path the existing routes should consume.
//
// A path is project-scoped iff, after stripping one leading "/", its first
// segment is "p" and its second segment is a valid project key. Then it
// returns (remaining, key) where remaining is the path with exactly "p/<key>/"
// removed (leading slash preserved). Otherwise it returns (path, "") and the
// caller routes exactly as before.
//
// A valid project key is non-empty and not "-". A single path segment can
// never contain "/", so that constraint is structural.
func ParseProjectPath(path string) (remaining, projectKey string) {
	s := strings.TrimPrefix(path, "/")
	segs := strings.Split(s, "/")
	if len(segs) < 2 || segs[0] != "p" {
		return path, ""
	}
	key := segs[1]
	if key == "" || key == "-" {
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
