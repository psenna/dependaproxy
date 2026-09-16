// Package oci implements the type: oci DependaProxy registry adapter: a
// pull-through proxy for the Docker Registry HTTP API v2 / OCI Distribution
// spec. See docs/superpowers/specs/2026-09-16-oci-registry-adapter-design.md.
package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Client fetches manifests and blobs from one upstream registry via
// go-containerregistry, which handles that registry's Bearer-auth handshake.
// v1 fetches anonymously only -- no private-registry credentials yet.
type Client struct {
	host string // upstream registry host[:port], no scheme, e.g. "registry-1.docker.io"
}

// NewClient builds a Client for upstreamURL (e.g. "https://registry-1.docker.io").
func NewClient(upstreamURL string) (*Client, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, fmt.Errorf("oci: parse upstream %q: %w", upstreamURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("oci: upstream %q has no host", upstreamURL)
	}
	return &Client{host: u.Host}, nil
}

// ManifestResult is a fetched manifest: its raw bytes (served verbatim to the
// client) and the digest computed HERE from those bytes -- never trusted
// verbatim from an upstream response header, so a compromised or
// misbehaving upstream cannot lie about what it served.
type ManifestResult struct {
	Bytes     []byte
	MediaType string
	Digest    string // "sha256:<hex>"
}

// GetManifest fetches the manifest for repoPath (e.g. "library/nginx") at ref
// (a tag like "latest", or a digest like "sha256:...").
func (c *Client) GetManifest(ctx context.Context, repoPath, ref string) (*ManifestResult, error) {
	refStr := c.host + "/" + repoPath + refSuffix(ref)
	r, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("oci: parse reference %q: %w", refStr, err)
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(desc.Manifest)
	return &ManifestResult{
		Bytes:     desc.Manifest,
		MediaType: string(desc.MediaType),
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

// GetBlob fetches the blob for repoPath at digest ("sha256:<hex>"), verifying
// the downloaded bytes hash to the requested digest before returning them --
// an upstream cannot serve the wrong bytes under a given digest without
// detection. Only the sha256 algorithm is supported; any other algorithm
// prefix is rejected rather than silently served unverified.
func (c *Client) GetBlob(ctx context.Context, repoPath, digest string) ([]byte, string, error) {
	if !strings.HasPrefix(digest, "sha256:") {
		return nil, "", fmt.Errorf("oci: unsupported digest algorithm in %q (only sha256 is verified)", digest)
	}
	refStr := c.host + "/" + repoPath + "@" + digest
	d, err := name.NewDigest(refStr)
	if err != nil {
		return nil, "", fmt.Errorf("oci: parse digest reference %q: %w", refStr, err)
	}
	layer, err := remote.Layer(d, remote.WithContext(ctx), remote.WithAuth(authn.Anonymous))
	if err != nil {
		return nil, "", err
	}
	rc, err := layer.Compressed()
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != digest {
		return nil, "", fmt.Errorf("oci: blob digest mismatch: requested %s, got %s", digest, got)
	}
	mt, err := layer.MediaType()
	if err != nil {
		return nil, "", err
	}
	return data, string(mt), nil
}

// refSuffix returns ":<ref>" for a tag or "@<ref>" for a digest. A digest is
// always of the form "<algorithm>:<hex>" and a Docker tag can never contain
// ":", so the presence of ":" unambiguously distinguishes them.
func refSuffix(ref string) string {
	if strings.Contains(ref, ":") {
		return "@" + ref
	}
	return ":" + ref
}
