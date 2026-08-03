package goproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a GOPROXY protocol HTTP client.
type Client struct {
	base string // upstream base URL, no trailing slash
	http *http.Client
}

// New returns a Go module proxy client for the upstream. If httpClient is nil a
// 30s-timeout client is used.
func New(upstream string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(upstream) == "" {
		return nil, fmt.Errorf("goproxy: upstream is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(upstream, "/"), http: httpClient}, nil
}

// URL builders. They use the ESCAPED module path, so an invalid module path
// surfaces as an error the caller can turn into a 400.

func (c *Client) listURL(module string) (string, error) {
	esc, err := escapePath(module)
	if err != nil {
		return "", err
	}
	return c.base + "/" + esc + "/@v/list", nil
}

func (c *Client) infoURL(module, version string) (string, error) {
	esc, err := escapePath(module)
	if err != nil {
		return "", err
	}
	return c.base + "/" + esc + "/@v/" + version + ".info", nil
}

func (c *Client) modURL(module, version string) (string, error) {
	esc, err := escapePath(module)
	if err != nil {
		return "", err
	}
	return c.base + "/" + esc + "/@v/" + version + ".mod", nil
}

func (c *Client) zipURL(module, version string) (string, error) {
	esc, err := escapePath(module)
	if err != nil {
		return "", err
	}
	return c.base + "/" + esc + "/@v/" + version + ".zip", nil
}

func (c *Client) latestURL(module string) (string, error) {
	esc, err := escapePath(module)
	if err != nil {
		return "", err
	}
	return c.base + "/" + esc + "/@latest", nil
}

// do performs a GET, handling 404 -> ErrNotFound and non-200 -> error. The
// caller owns resp.Body on success.
func (c *Client) do(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // G704: target is the operator-configured upstream URL; a proxy fetches upstream by design
	if err != nil {
		return nil, fmt.Errorf("goproxy: build request for %s: %w", target, err)
	}
	resp, err := c.http.Do(req) //nolint:gosec // G704: outbound fetch to the configured upstream
	if err != nil {
		return nil, fmt.Errorf("goproxy: fetch %s: %w", target, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		closeQuiet(resp.Body)
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		closeQuiet(resp.Body)
		return nil, fmt.Errorf("goproxy: %s: %s", target, resp.Status)
	}
	return resp, nil
}

// FetchList returns the version list (one per line) for a module.
func (c *Client) FetchList(ctx context.Context, module string) ([]string, error) {
	target, err := c.listURL(module)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("goproxy: read list %s: %w", target, err)
	}
	versions := strings.Split(string(b), "\n")
	// Drop a single trailing empty element produced by the trailing newline.
	if len(versions) > 0 && versions[len(versions)-1] == "" {
		versions = versions[:len(versions)-1]
	}
	return versions, nil
}

// FetchInfo returns the .info document for a module version.
func (c *Client) FetchInfo(ctx context.Context, module, version string) (*Info, error) {
	target, err := c.infoURL(module, version)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("goproxy: decode info %s/%s: %w", module, version, err)
	}
	return &info, nil
}

// FetchMod returns the go.mod file bytes for a module version.
func (c *Client) FetchMod(ctx context.Context, module, version string) ([]byte, error) {
	target, err := c.modURL(module, version)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("goproxy: read mod %s: %w", target, err)
	}
	return b, nil
}

// FetchZip streams the module zip archive. The caller owns the body.
func (c *Client) FetchZip(ctx context.Context, module, version string) (io.ReadCloser, int64, error) {
	target, err := c.zipURL(module, version)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// FetchLatest returns the @latest document for a module.
func (c *Client) FetchLatest(ctx context.Context, module string) (*Info, error) {
	target, err := c.latestURL(module)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("goproxy: decode latest %s: %w", module, err)
	}
	return &info, nil
}

func closeQuiet(c io.Closer) { _ = c.Close() }
