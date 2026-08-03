package pypi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	acceptJSON = "application/vnd.pypi.simple.v1+json"
	acceptHTML = "text/html"
)

var normRe = regexp.MustCompile(`[-_.]+`)

// NormalizeName applies PEP 503 normalization: lowercase, collapse runs of
// [-_.] to a single "-".
func NormalizeName(name string) string {
	return normRe.ReplaceAllString(strings.ToLower(name), "-")
}

// Client is a PyPI simple-API HTTP client.
type Client struct {
	base string // upstream base URL, no trailing slash (e.g. https://pypi.org/simple)
	http *http.Client
}

// New returns a pypi client for the upstream simple index.
func New(upstream string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(upstream) == "" {
		return nil, fmt.Errorf("pypi: upstream is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(upstream, "/"), http: httpClient}, nil
}

func (c *Client) indexURL(name string) string { return c.base + "/" + NormalizeName(name) + "/" }

func (c *Client) do(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // G704: operator-configured upstream URL
	if err != nil {
		return nil, fmt.Errorf("pypi: build request for %s: %w", target, err)
	}
	resp, err := c.http.Do(req) //nolint:gosec // G704: outbound fetch to the configured upstream
	if err != nil {
		return nil, fmt.Errorf("pypi: fetch %s: %w", target, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		closeQuiet(resp.Body)
		return nil, ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		closeQuiet(resp.Body)
		return nil, fmt.Errorf("pypi: %s: %s", target, resp.Status)
	}
	return resp, nil
}

// FetchIndex decodes the trimmed project model as PEP 691 JSON.
func (c *Client) FetchIndex(ctx context.Context, name string) (*Project, error) {
	resp, err := c.do(ctx, c.indexURL(name))
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	var p Project
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("pypi: decode index %s: %w", name, err)
	}
	return &p, nil
}

// FetchIndexRaw returns the upstream index body verbatim + its content-type.
func (c *Client) FetchIndexRaw(ctx context.Context, name, accept string) ([]byte, string, error) {
	target := c.indexURL(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // G704
	if err != nil {
		return nil, "", fmt.Errorf("pypi: build request for %s: %w", target, err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req) //nolint:gosec // G704
	if err != nil {
		return nil, "", fmt.Errorf("pypi: fetch %s: %w", target, err)
	}
	defer closeQuiet(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("pypi: %s: %s", target, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("pypi: read index %s: %w", name, err)
	}
	return b, resp.Header.Get("Content-Type"), nil
}

// FetchFile streams the artifact at fileURL. The caller owns the body.
func (c *Client) FetchFile(ctx context.Context, fileURL string) (io.ReadCloser, int64, error) {
	if _, err := url.Parse(fileURL); err != nil {
		return nil, 0, fmt.Errorf("pypi: invalid file url: %w", err)
	}
	resp, err := c.do(ctx, fileURL)
	if err != nil {
		return nil, 0, err
	}
	return resp.Body, resp.ContentLength, nil
}

// FetchAttestations fetches the PEP 740 attestation document for a project
// version (GET <base>/<NormalizeName(name)>/<version>/attestations/). 404 ->
// ErrNotFound (no attestations published); the body is returned verbatim.
func (c *Client) FetchAttestations(ctx context.Context, name, version string) ([]byte, error) {
	target := c.base + "/" + NormalizeName(name) + "/" + version + "/attestations/"
	resp, err := c.do(ctx, target)
	if err != nil {
		return nil, err
	}
	defer closeQuiet(resp.Body)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pypi: read attestations %s@%s: %w", name, version, err)
	}
	return b, nil
}

func closeQuiet(c io.Closer) { _ = c.Close() }
