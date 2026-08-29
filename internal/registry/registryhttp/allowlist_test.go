package registryhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeResolver returns canned IPs for a hostname, avoiding real DNS in tests.
type fakeResolver struct {
	ips map[string][]net.IP
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}

func mustAllowlist(t *testing.T, base string, extra ...string) *Allowlist {
	t.Helper()
	a, err := NewAllowlist(base, extra)
	if err != nil {
		t.Fatalf("NewAllowlist(%q, %v): %v", base, extra, err)
	}
	return a
}

func TestAllowlistedIPLiteralAllowed(t *testing.T) {
	a := mustAllowlist(t, "http://127.0.0.1:8080")
	if err := a.CheckURL(context.Background(), "http://127.0.0.1:8080/pkg.tgz"); err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
}

func TestNonAllowlistedHostRejected(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http://evil.example.com/x"); err == nil {
		t.Fatal("want error for non-allowlisted host")
	}
}

func TestCloudMetadataIPRejected(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Fatal("want error for cloud metadata IP")
	}
}

func TestLoopbackIPRejectedUnlessBase(t *testing.T) {
	// Not allowlisted -> rejected.
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http://127.0.0.1/x"); err == nil {
		t.Fatal("want error for non-allowlisted loopback IP")
	}
	// As the base upstream -> allowed without resolution.
	b := mustAllowlist(t, "http://127.0.0.1:8080")
	if err := b.CheckURL(context.Background(), "http://127.0.0.1:8080/x"); err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
}

func TestLocalhostRejectedUnlessBase(t *testing.T) {
	// Base is not localhost -> rejected.
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http://localhost/x"); err == nil {
		t.Fatal("want error for localhost when base is not localhost")
	}
	// Base IS localhost -> allowed (fake resolver returns a public IP so the
	// allowlisted hostname passes the resolution check without real DNS).
	b := mustAllowlist(t, "http://localhost:8080")
	b.resolver = &fakeResolver{ips: map[string][]net.IP{
		"localhost": {net.ParseIP("93.184.216.34")},
	}}
	if err := b.CheckURL(context.Background(), "http://localhost:8080/x"); err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
}

func TestNonHTTPSchemesRejected(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com")
	for _, u := range []string{"file:///etc/passwd", "gopher://registry.example.com/x", "ftp://registry.example.com/x"} {
		if err := a.CheckURL(context.Background(), u); err == nil {
			t.Errorf("want error for %q", u)
		}
	}
}

func TestEmptyHostRejected(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http:///x"); err == nil {
		t.Fatal("want error for empty host")
	}
}

func TestIPv6LoopbackRejected(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com")
	if err := a.CheckURL(context.Background(), "http://[::1]/x"); err == nil {
		t.Fatal("want error for IPv6 loopback")
	}
}

func TestRedirectToInternalRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	a := mustAllowlist(t, srv.URL)
	hc := a.WrapClient(nil)
	resp, err := hc.Get(srv.URL + "/start")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("want error following redirect to internal host")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") {
		t.Errorf("err = %v, want mention of internal host", err)
	}
}

func TestHostnameResolvingToPrivateIPRejected(t *testing.T) {
	// cdn.example.com is allowlisted but DNS-rebounds to a private IP.
	a := mustAllowlist(t, "http://registry.example.com", "cdn.example.com")
	a.resolver = &fakeResolver{ips: map[string][]net.IP{
		"cdn.example.com": {net.ParseIP("10.0.0.1")},
	}}
	if err := a.CheckURL(context.Background(), "http://cdn.example.com/x"); err == nil {
		t.Fatal("want error for allowlisted hostname resolving to private IP")
	}
}

func TestHostnameResolvingToPublicIPAllowed(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com", "cdn.example.com")
	a.resolver = &fakeResolver{ips: map[string][]net.IP{
		"cdn.example.com": {net.ParseIP("93.184.216.34")},
	}}
	if err := a.CheckURL(context.Background(), "http://cdn.example.com/x"); err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
}

func TestDNSFailureFailsClosed(t *testing.T) {
	a := mustAllowlist(t, "http://registry.example.com", "cdn.example.com")
	a.resolver = &fakeResolver{ips: map[string][]net.IP{}}
	if err := a.CheckURL(context.Background(), "http://cdn.example.com/x"); err == nil {
		t.Fatal("want error when DNS resolution fails")
	}
}

func TestAllowlistAllows(t *testing.T) {
	a := mustAllowlist(t, "https://pypi.org/simple", "files.pythonhosted.org")
	if !a.Allows("pypi.org") {
		t.Error("base host pypi.org should be allowed")
	}
	if !a.Allows("files.pythonhosted.org") {
		t.Error("extra host files.pythonhosted.org should be allowed")
	}
	if !a.Allows("Files.PythonHosted.Org.") {
		t.Error("host match must be case-insensitive and trailing-dot tolerant")
	}
	if !a.Allows("files.pythonhosted.org:8443") {
		t.Error("a host:port must match the hostname-only entry (CheckURL compares hostnames too)")
	}
	if a.Allows("evil.example.com") {
		t.Error("unknown host must not be allowed")
	}
	if a.Allows("evil.example.com:443") {
		t.Error("unknown host with a port must not be allowed")
	}
	if a.Allows("") {
		t.Error("empty host must not be allowed")
	}
	if (*Allowlist)(nil).Allows("x") {
		t.Error("nil Allowlist must allow nothing")
	}
}

func TestRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/loop", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	a := mustAllowlist(t, srv.URL)
	hc := a.WrapClient(nil)
	resp, err := hc.Get(srv.URL + "/start")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("want error after too many redirects")
	}
}
