package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestNewJSONLevelDebug emits debug-level records when the configured level is
// debug, in JSON, with the expected keys.
func TestNewJSONLevelDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWith(&buf, "json", "debug")
	logger.Debug("low level", "pkg", "hash")
	logger.Info("normal", "pkg", "hash")

	var seen []map[string]any
	dec := json.NewDecoder(&buf)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode: %v", err)
		}
		seen = append(seen, m)
	}
	if len(seen) != 2 {
		t.Fatalf("want 2 records, got %d (%v)", len(seen), buf.String())
	}
	if seen[0]["level"] != "DEBUG" || seen[0]["msg"] != "low level" {
		t.Errorf("record 0 = %v", seen[0])
	}
	if seen[0]["pkg"] != "hash" {
		t.Errorf("attr pkg = %v", seen[0]["pkg"])
	}
	if seen[1]["level"] != "INFO" || seen[1]["msg"] != "normal" {
		t.Errorf("record 1 = %v", seen[1])
	}
}

// TestNewJSONLevelWarn suppresses debug and info records when the configured
// level is warn.
func TestNewJSONLevelWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := NewWith(&buf, "json", "warn")
	logger.Debug("should be dropped")
	logger.Info("also dropped")
	logger.Warn("kept")

	out := buf.String()
	if strings.Contains(out, "dropped") {
		t.Fatalf("debug/info leaked at warn level: %q", out)
	}
	if !strings.Contains(out, "kept") {
		t.Fatalf("warn record missing: %q", out)
	}
}

// TestLevelParsing maps the config level string to the slog level.
func TestLevelParsing(t *testing.T) {
	cases := []struct {
		level string
		want  string // expected emitted level for an Info record, or "" if suppressed
	}{
		{"debug", "INFO"},
		{"info", "INFO"},
		{"warn", ""},
		{"error", ""},
		{"", "INFO"},      // default -> info
		{"BOGUS", "INFO"}, // unknown -> info
	}
	for _, c := range cases {
		var buf bytes.Buffer
		l := NewWith(&buf, "json", c.level)
		l.Info("x")
		if c.want == "" {
			if buf.Len() != 0 {
				t.Errorf("level %q: info leaked: %q", c.level, buf.String())
			}
			continue
		}
		var m map[string]any
		if err := json.NewDecoder(&buf).Decode(&m); err != nil {
			t.Fatalf("level %q decode: %v (%q)", c.level, err, buf.String())
		}
		if m["level"] != c.want {
			t.Errorf("level %q: got %v want %s", c.level, m["level"], c.want)
		}
	}
}

// TestFormatText produces text format (key=value) for format=text.
func TestFormatText(t *testing.T) {
	var buf bytes.Buffer
	l := NewWith(&buf, "text", "info")
	l.Info("hello", "pkg", "hash")
	out := buf.String()
	if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "pkg=hash") {
		t.Fatalf("text format wrong: %q", out)
	}
}

// TestNewDefaults writes to os.Stdout with JSON+info (smoke; just ensure no panic).
func TestNewNoPanic(t *testing.T) {
	if l := New("json", "info"); l == nil {
		t.Fatal("New returned nil logger")
	}
}
