// Package log is a thin wrapper over the standard library's log/slog,
// providing structured logging configured by a format and level string. No
// external logging dependency.
package log

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a structured logger writing to os.Stdout using the given format
// ("json" or "text") and level ("debug", "info", "warn", "error"). Unknown
// format defaults to JSON; unknown/empty level defaults to info.
func New(format, level string) *slog.Logger {
	return NewWith(os.Stdout, format, level)
}

// NewWith is the testable form of New: it writes to w instead of os.Stdout.
func NewWith(w io.Writer, format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default: // "" and unknown -> info
		return slog.LevelInfo
	}
}
