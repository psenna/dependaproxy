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

// packumentURL returns the upstream packument URL for name (scoped names are
// URL-safe and the path is literal).
func (c *Client) packumentURL(name string) string { return c.base + "/" + name }

// do performs a GET, handling 404 -> ErrNotFound and non-200 -> error. The
// caller owns resp.Body on success.
func (c *Client) do(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("npm: build request for %s: %w", url, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm: fetch %s: %w", url, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		closeQuiet(resp.Body)
		return nil, registry.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		closeQuiet(resp.Body)
		return nil, fmt.Errorf("npm: %s: %s", url, resp.Status)
	}
	return resp, nil
}

// FetchPackument GETs <upstream>/<name> and decodes the packument (trimmed).
// Unknown fields are ignored (permissive decode). A 404 yields ErrNotFound.
func (c *Client) FetchPackument(ctx context.Context, name string) (*registry.Packument, error) {
	resp, err := c.do(ctx, c.packumentURL(name))
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	var p registry.Packument
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("npm: decode packument %s: %w", name, err)
	}
	return &p, nil
}

// FetchPackumentRaw returns the full upstream packument JSON for name verbatim.
// A 404 yields ErrNotFound. Used to serve clients with every field preserved.
func (c *Client) FetchPackumentRaw(ctx context.Context, name string) ([]byte, error) {
	resp, err := c.do(ctx, c.packumentURL(name))
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("npm: read packument %s: %w", name, err)
	}
	return b, nil
}

// FetchTarball streams the tarball at tarballURL (an absolute URL from the
// packument's dist.tarball). The caller owns the returned ReadCloser.
func (c *Client) FetchTarball(ctx context.Context, tarballURL string) (io.ReadCloser, int64, error) {
	if _, err := url.Parse(tarballURL); err != nil {
		return nil, 0, fmt.Errorf("npm: invalid tarball url: %w", err)
	}
	resp, err := c.do(ctx, tarballURL)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// closeQuiet closes c, ignoring the returned error (used for cleanup paths
// where the error is not actionable).
func closeQuiet(c io.Closer) { _ = c.Close() }
