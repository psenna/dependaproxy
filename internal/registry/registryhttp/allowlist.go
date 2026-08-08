// Package registryhttp hardens upstream registry HTTP clients against SSRF:
// every URL the proxy fetches on behalf of an upstream (packuments, indexes,
// tarballs, provenance bundles) is validated against an allowlist of permitted
// hosts before the request is made, and again on every redirect hop.
package registryhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Resolver resolves a hostname to IP addresses. *net.Resolver satisfies it;
// tests inject a fake to avoid real DNS.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Allowlist is the set of hosts a registry client may fetch from: the base
// upstream host, adapter-shipped default extra hosts (e.g. PyPI's
// files.pythonhosted.org), and operator-configured allowed_upstream_hosts.
type Allowlist struct {
	hosts    map[string]struct{}
	resolver Resolver
}

// NewAllowlist builds an Allowlist from the base upstream URL and any extra
// hosts. The base URL must parse and carry a host.
func NewAllowlist(baseURL string, extraHosts []string) (*Allowlist, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("registryhttp: parse base upstream %q: %w", baseURL, err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("registryhttp: base upstream %q has no host", baseURL)
	}
	a := &Allowlist{hosts: map[string]struct{}{}, resolver: net.DefaultResolver}
	a.add(u.Hostname())
	for _, h := range extraHosts {
		a.add(h)
	}
	return a, nil
}

// add normalizes and records a host. Empty entries are ignored.
func (a *Allowlist) add(host string) {
	if h := normalizeHost(host); h != "" {
		a.hosts[h] = struct{}{}
	}
}

// normalizeHost lowercases, trims whitespace and a trailing dot. Hosts are
// compared on hostname only (any port is allowed).
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// CheckURL validates that rawURL is http/https and its host is allowlisted.
// For hostnames (not IP literals) the host is resolved and rejected if any
// A/AAAA address is loopback, private, link-local, link-local-multicast,
// unspecified, or multicast. Allowlisted IP literals are allowed without
// resolution. DNS errors fail closed.
func (a *Allowlist) CheckURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("registryhttp: parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("registryhttp: scheme %q not allowed", u.Scheme)
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return fmt.Errorf("registryhttp: empty host")
	}
	if _, ok := a.hosts[host]; !ok {
		return fmt.Errorf("registryhttp: host %q not allowlisted", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil // allowlisted IP literal: allowed without resolution
	}
	addrs, err := a.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("registryhttp: resolve %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := addr.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("registryhttp: host %q resolves to disallowed address %s", host, ip)
		}
	}
	return nil
}

// CheckRedirect is an http.Client.CheckRedirect that validates every redirect
// hop against the allowlist and enforces a 10-hop limit (mirroring the
// stdlib default policy, which is bypassed when CheckRedirect is set).
func (a *Allowlist) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("registryhttp: stopped after 10 redirects")
	}
	if err := a.CheckURL(req.Context(), req.URL.String()); err != nil {
		return fmt.Errorf("registryhttp: redirect to %s: %w", req.URL, err)
	}
	return nil
}

// WrapClient installs CheckRedirect on hc and returns it. If hc is nil a
// 30s-timeout client is built. The transport and timeout of a non-nil client
// are preserved.
func (a *Allowlist) WrapClient(hc *http.Client) *http.Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	hc.CheckRedirect = a.CheckRedirect
	return hc
}
