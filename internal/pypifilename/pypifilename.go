// Package pypifilename parses PyPI artifact filenames (wheels and sdists) into
// the distribution name + version + compatibility tags used to key the per-file
// trust store and to route file requests. Wheel names follow PEP 427/491/425/600:
//
//	{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
//
// sdists follow PEP 625: {name}-{version}.tar.gz (legacy .zip also seen).
package pypifilename

import (
	"fmt"
	"strings"
)

// Info is the parsed filename.
type Info struct {
	Name        string // distribution name as encoded in the filename (PEP 427 escaped, NOT PEP 503 normalized)
	Version     string
	FileType    string // "wheel" | "sdist"
	PythonTag   string // wheel only; "" for sdist
	AbiTag      string // wheel only; "" for sdist
	PlatformTag string // wheel only; "" for sdist
}

// Parse parses a PyPI artifact filename. Wheels are identified by the .whl
// suffix; everything else is treated as an sdist (.tar.gz, .zip, ...).
func Parse(filename string) (Info, error) {
	if filename == "" {
		return Info{}, fmt.Errorf("pypifilename: empty filename")
	}
	if strings.HasSuffix(filename, ".whl") {
		return parseWheel(filename)
	}
	return parseSdist(filename), nil
}

func parseWheel(filename string) (Info, error) {
	name := strings.TrimSuffix(filename, ".whl")
	parts := strings.Split(name, "-")
	// distribution, version, (build?), python, abi, platform => 5 or 6 parts.
	if len(parts) < 5 {
		return Info{}, fmt.Errorf("pypifilename: invalid wheel filename %q", filename)
	}
	return Info{
		Name:        parts[0],
		Version:     parts[1],
		FileType:    "wheel",
		PythonTag:   parts[len(parts)-3],
		AbiTag:      parts[len(parts)-2],
		PlatformTag: parts[len(parts)-1],
	}, nil
}

func parseSdist(filename string) Info {
	name := filename
	for _, suf := range []string{".tar.gz", ".zip"} {
		if strings.HasSuffix(name, suf) {
			name = strings.TrimSuffix(name, suf)
			break
		}
	}
	out := Info{Version: name, FileType: "sdist"}
	if idx := strings.LastIndex(name, "-"); idx >= 0 {
		out.Name = name[:idx]
		out.Version = name[idx+1:]
	}
	return out
}

// ParseVersion returns just the version parsed from the filename.
func ParseVersion(filename string) (string, error) {
	i, err := Parse(filename)
	if err != nil {
		return "", err
	}
	return i.Version, nil
}

// ParseName returns just the distribution name parsed from the filename (PEP
// 427 for wheels, PEP 625 for sdists). Like ParseVersion, it returns an error
// only for an empty filename or a malformed wheel; a degenerate sdist with no
// "-" returns ("", nil). Callers must check both err and name == "".
func ParseName(filename string) (string, error) {
	i, err := Parse(filename)
	if err != nil {
		return "", err
	}
	return i.Name, nil
}
