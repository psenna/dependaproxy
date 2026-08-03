package goproxy

import "golang.org/x/mod/module"

// escapePath returns the escaped form of a module path (each uppercase letter
// prefixed with "!" and lowercased), as used in GOPROXY URL paths.
func escapePath(path string) (string, error) { return module.EscapePath(path) }

// unescapePath returns the original module path for an escaped GOPROXY URL
// path element. It fails if the escaped form is invalid.
func unescapePath(escaped string) (string, error) { return module.UnescapePath(escaped) }
