package pypifilename

import "testing"

func TestParseWheel(t *testing.T) {
	cases := []struct {
		filename               string
		ver, ft, py, abi, plat string
	}{
		{"numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl", "1.26.0", "wheel", "cp312", "cp312", "manylinux_2_17_x86_64"},
		{"foo_bar-2.3.4-py3-none-any.whl", "2.3.4", "wheel", "py3", "none", "any"},
		{"pkg-1.0.0-1-py3-none-any.whl", "1.0.0", "wheel", "py3", "none", "any"}, // build tag ignored
	}
	for _, c := range cases {
		i, err := Parse(c.filename)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.filename, err)
		}
		if i.Version != c.ver || i.FileType != c.ft || i.PythonTag != c.py || i.AbiTag != c.abi || i.PlatformTag != c.plat {
			t.Errorf("Parse(%q) = %+v, want ver=%s ft=%s py=%s abi=%s plat=%s", c.filename, i, c.ver, c.ft, c.py, c.abi, c.plat)
		}
	}
}

func TestParseSdist(t *testing.T) {
	cases := []struct {
		filename, ver string
	}{
		{"foo-1.0.0.tar.gz", "1.0.0"},
		{"my-pkg-1.0.tar.gz", "1.0"},
		{"bar-2.3.4.zip", "2.3.4"},
	}
	for _, c := range cases {
		i, err := Parse(c.filename)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.filename, err)
		}
		if i.Version != c.ver || i.FileType != "sdist" || i.PythonTag != "" || i.AbiTag != "" || i.PlatformTag != "" {
			t.Errorf("Parse(%q) = %+v, want sdist ver=%s tags empty", c.filename, i, c.ver)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse(""); err == nil {
		t.Fatal("want error for empty filename")
	}
	if _, err := Parse("bad.whl"); err == nil {
		t.Fatal("want error for malformed wheel")
	}
}

func TestParseVersion(t *testing.T) {
	v, err := ParseVersion("numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl")
	if err != nil || v != "1.26.0" {
		t.Fatalf("ParseVersion = %q err=%v", v, err)
	}
}

// TestParseVersionEmpty locks the exact condition rewriteIndexJSON and
// handleFile rely on: a degenerate sdist whose name strips to empty parses
// with a nil error but an empty version, while a malformed wheel errors.
func TestParseVersionEmpty(t *testing.T) {
	v, err := ParseVersion(".tar.gz")
	if err != nil {
		t.Fatalf("ParseVersion(.tar.gz) err=%v, want nil", err)
	}
	if v != "" {
		t.Errorf("ParseVersion(.tar.gz) = %q, want \"\"", v)
	}
	if v, err := ParseVersion("bad.whl"); err == nil {
		t.Errorf("ParseVersion(bad.whl) = %q err=nil, want error", v)
	}
}
