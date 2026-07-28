// Package npm implements registry.RegistryClient against an npm-compatible
// upstream registry (e.g. https://registry.npmjs.org). It uses only the
// standard library.
package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/psenna/dependaproxy/internal/registry"
)

// Client is an npm registry client.
type Client struct {
	base string // upstream base URL, no trailing slash
	http *http.Client
}

// New returns an npm client for the upstream registry. If httpClient is nil a
// client with a 30s timeout is used.
func New(upstream string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(upstream) == "" {
		return nil, fmt.Errorf("npm: upstream is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(upstream, "/"), http: httpClient}, nil
}

// FetchPackument GETs <upstream>/<name> and decodes the packument. Unknown
// fields are ignored (permissive decode). A 404 yields registry.ErrNotFound.
func (c *Client) FetchPackument(ctx context.Context, name string) (*registry.Packument, error) {
	// name may be scoped (@org/pkg); it is URL-safe and the path is literal.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/"+name, nil)
	if err != nil {
		return nil, fmt.Errorf("npm: build packument request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch packument %s: %w", name, err)
	}
	defer closeQuiet(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, registry.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm: packument %s: %s", name, resp.Status)
	}
	var p registry.Packument
	// json.Decode ignores unknown fields (permissive).
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("npm: decode packument %s: %w", name, err)
	}
	return &p, nil
}

// FetchTarball streams the tarball at tarballURL (an absolute URL from the
// packument's dist.tarball). The caller owns the returned ReadCloser.
func (c *Client) FetchTarball(ctx context.Context, tarballURL string) (io.ReadCloser, int64, error) {
	if _, err := url.Parse(tarballURL); err != nil {
		return nil, 0, fmt.Errorf("npm: invalid tarball url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("npm: build tarball request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("npm: fetch tarball: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		closeQuiet(resp.Body)
		return nil, 0, registry.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		closeQuiet(resp.Body)
		return nil, 0, fmt.Errorf("npm: tarball: %s", resp.Status)
	}
	return resp.Body, resp.ContentLength, nil
}

// closeQuiet closes c, ignoring the returned error (used for cleanup paths
// where the error is not actionable).
func closeQuiet(c io.Closer) { _ = c.Close() }
