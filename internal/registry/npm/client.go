package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/psenna/dependaproxy/internal/registry/registryhttp"
)

// Client is an npm registry HTTP client.
type Client struct {
	base  string // upstream base URL, no trailing slash
	http  *http.Client
	allow *registryhttp.Allowlist
}

// New returns an npm client for the upstream registry. extraAllowedHosts are
// additional hosts (beyond the base upstream host) the client may fetch from,
// e.g. operator-configured CDN mirrors. If httpClient is nil a 30s-timeout
// client is used. Every fetch is validated against the host allowlist to
// prevent SSRF via upstream-advertised URLs.
func New(upstream string, extraAllowedHosts []string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(upstream) == "" {
		return nil, fmt.Errorf("npm: upstream is required")
	}
	allow, err := registryhttp.NewAllowlist(upstream, extraAllowedHosts)
	if err != nil {
		return nil, fmt.Errorf("npm: %w", err)
	}
	return &Client{
		base:  strings.TrimRight(upstream, "/"),
		http:  allow.WrapClient(httpClient),
		allow: allow,
	}, nil
}

func (c *Client) packumentURL(name string) string { return c.base + "/" + name }

// do performs a GET, handling 404 -> ErrNotFound and non-200 -> error. The
// caller owns resp.Body on success. The target is validated against the host
// allowlist before the request is made.
func (c *Client) do(ctx context.Context, target string) (*http.Response, error) {
	if err := c.allow.CheckURL(ctx, target); err != nil {
		return nil, fmt.Errorf("npm: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // G704: target is the operator-configured upstream URL; a proxy fetches upstream by design
	if err != nil {
		return nil, fmt.Errorf("npm: build request for %s: %w", target, err)
	}
	resp, err := c.http.Do(req) //nolint:gosec // G704: outbound fetch to the configured upstream
	if err != nil {
		return nil, fmt.Errorf("npm: fetch %s: %w", target, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		closeQuiet(resp.Body)
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		closeQuiet(resp.Body)
		return nil, fmt.Errorf("npm: %s: %s", target, resp.Status)
	}
	return resp, nil
}

// FetchPackument decodes the trimmed packument. Unknown fields are ignored.
func (c *Client) FetchPackument(ctx context.Context, name string) (*Packument, error) {
	resp, err := c.do(ctx, c.packumentURL(name))
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	var p Packument
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("npm: decode packument %s: %w", name, err)
	}
	return &p, nil
}

// FetchPackumentRaw returns the full upstream packument JSON verbatim.
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

// FetchBytes GETs an arbitrary URL (e.g. a dist.attestations.url provenance
// bundle) and returns the body verbatim. 404 -> ErrNotFound.
func (c *Client) FetchBytes(ctx context.Context, target string) ([]byte, error) {
	if _, err := url.Parse(target); err != nil {
		return nil, fmt.Errorf("npm: invalid url: %w", err)
	}
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("npm: read %s: %w", target, err)
	}
	return b, nil
}

// FetchTarball streams the tarball at tarballURL. The caller owns the body.
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

func closeQuiet(c io.Closer) { _ = c.Close() }
