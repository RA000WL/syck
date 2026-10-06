package internalurl

import (
	"net"
	"testing"

	"github.com/RA000WL/syck/internal/netguard"
)

// This package is the single source of truth for "is this URL internal?".
// These tables pin the semantics BEFORE anything uses them. Do not relax a
// case to match a code change: a failing case here is a security regression
// (an internal URL silently classified as public), not a stale expectation.

// TestHostOf pins the shared host extractor. Three traps live in this helper,
// and every one of them silently turns a security predicate into a no-op:
//
//  1. url.Parse finds no host in a bare "10.0.0.1" (it lands in Path), so a
//     naive u.Hostname() returns "" and IsPrivateHost is false for the exact
//     input it exists to catch.
//  2. url.Parse REJECTS "172.16.5.4:8080" and "[::1]" outright, so an
//     err-nil-only implementation drops every bare host:port and bare IPv6.
//  3. netguard.IsMetadataHost takes a BARE hostname, not host:port. Passing
//     u.Host instead of u.Hostname() lets "metadata.google.internal:8080"
//     through as a non-metadata host — an SSRF bypass.
func TestHostOf(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		// Scheme + authority present: the parsed hostname wins.
		{"scheme-http", "http://10.0.0.1/", "10.0.0.1"},
		{"scheme-https", "https://example.com/x?y=1#z", "example.com"},
		{"scheme-uppercase", "HTTP://EXAMPLE.COM/x", "example.com"},
		{"port-stripped", "http://10.0.0.1:8080/x", "10.0.0.1"},
		{"userinfo-stripped", "http://user:pw@10.0.0.1/x", "10.0.0.1"},
		{"protocol-relative", "//example.com/x", "example.com"},
		{"braced-ipv6", "http://[::1]:8080/x", "::1"},
		{"braced-ipv6-no-port", "http://[::1]/", "::1"},
		// TRAP 3: u.Host would keep the :8080 here and IsMetadataHost would
		// not match. Hostname() strips it.
		{"metadata-host-with-port", "http://metadata.google.internal:8080/", "metadata.google.internal"},

		// No scheme: url.Parse puts the whole thing in Path.
		{"bare-ipv4", "10.0.0.1", "10.0.0.1"},
		{"bare-ipv4-with-path", "192.168.1.1/admin", "192.168.1.1"},
		{"bare-ipv4-with-query", "10.0.0.1?a=b", "10.0.0.1"},
		{"bare-hostname", "localhost", "localhost"},
		{"bare-hostname-uppercase", "LocalHost", "localhost"},
		{"bare-opaque-scheme-lookalike", "localhost:3000", "localhost"},
		// TRAP 2: url.Parse errors on this. The host is still the host.
		{"bare-ipv4-with-port", "172.16.5.4:8080", "172.16.5.4"},
		{"bare-braced-ipv6", "[::1]", "::1"},
		{"bare-braced-ipv6-with-port", "[::1]:8080", "::1"},
		{"bare-ipv6", "::1", "::1"},
		{"bare-ipv6-full", "2001:db8::1", "2001:db8::1"},

		// Trailing root dot is normalized away, matching netguard's own
		// IsMetadataHost policy. Without this, "localhost." (which recon's
		// \b-terminated regex DOES match today) would become non-loopback.
		{"trailing-dot-host", "http://127.0.0.1./", "127.0.0.1"},
		{"trailing-dot-metadata", "metadata.google.internal.", "metadata.google.internal"},
		{"trailing-dot-loopback-name", "localhost.", "localhost"},

		// Nothing host-shaped in the input.
		{"empty", "", ""},
		{"path-only", "/admin/x", ""},
		{"scheme-no-host", "http:///p", ""},
		{"port-only", ":5432", ""},
		{"scheme-relative-empty", "//", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostOf(tc.raw); got != tc.want {
				t.Errorf("hostOf(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsPrivateHost pins the three RFC 1918 ranges and, critically, the fact
// that loopback and link-local are NOT private. IsPrivateHost must be the
// NARROW predicate: netguard.IsBlockedIP would also return true for
// 127.0.0.1 and 169.254.169.254, and classifyInternal relies on those landing
// in the "localhost" and "cloud_metadata" categories instead.
func TestIsPrivateHost(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"10-8", "http://10.0.0.1/", true},
		{"10-8-with-port", "10.0.0.1:8080", true},
		{"10-8-with-path", "192.168.1.1/admin", true},
		{"10-8-bare", "10.1.2.3", true},
		{"10-8-first", "10.0.0.0", true},
		{"10-8-last", "10.255.255.255", true},
		{"172-16-12", "172.16.5.4:8080", true},
		{"172-16-12-first", "172.16.0.0", true},
		{"172-16-12-last", "172.31.255.255", true},
		{"192-168-16", "http://192.168.1.1/admin", true},
		{"192-168-16-first", "192.168.0.0", true},
		{"192-168-16-last", "192.168.255.255", true},
		{"v4-mapped-private", "http://[::ffff:10.0.0.1]/x", true},

		// Just outside every range.
		{"below-10-8", "9.255.255.255", false},
		{"above-10-8", "11.0.0.0", false},
		{"below-172-16-12", "172.15.255.255", false},
		{"above-172-16-12", "172.32.0.1", false},
		{"below-192-168-16", "192.167.255.255", false},
		{"above-192-168-16", "192.169.0.1", false},
		{"public-v4", "https://8.8.8.8/", false},
		{"public-dns", "https://example.com/", false},

		// Loopback and link-local are blocked for fetching, but they are not
		// PRIVATE. If any of these return true, recon's categories collapse.
		{"loopback-is-not-private", "http://127.0.0.1/", false},
		{"link-local-is-not-private", "http://169.254.169.254/", false},
		{"unspecified-is-not-private", "http://0.0.0.0/", false},
		{"ipv6-loopback-is-not-private", "http://[::1]/", false},

		// A private IP in the PATH is not a private host. This is the
		// intentional Task 4 delta; recon's old regex text-matched it.
		{"private-ip-in-path", "http://foo.com/10.0.0.1/x", false},
		{"private-ip-in-query", "http://foo.com/?host=192.168.1.1", false},

		{"empty", "", false},
		{"path-only", "/admin", false},
		{"hostname-with-digits", "http://10.0.0.1.example.com/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPrivateHost(tc.raw); got != tc.want {
				t.Errorf("IsPrivateHost(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsLoopback pins 127/8, ::1, the unspecified address, and the literal
// name "localhost".
//
// The "localhost" case is the deliberate divergence from netguard, which
// allows the DNS name because it does no resolution. IsLoopback classifies a
// URL somebody typed, so the name itself is the signal. Do not "unify" the
// two layers.
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"127-0-0-1", "http://127.0.0.1:8080/", true},
		{"127-0-0-5", "http://127.0.0.5/", true},
		{"127-0-1-2-3", "http://127.1.2.3/", true},
		{"127-8-first", "http://127.0.0.0/", true},
		{"127-8-last", "http://127.255.255.255/", true},
		{"127-8-bare", "127.0.0.1:8080", true},
		{"ipv6-loopback", "http://[::1]/", true},
		{"ipv6-loopback-with-port", "http://[::1]:8080/x", true},
		{"ipv6-loopback-bare", "::1", true},
		{"unspecified-v4", "http://0.0.0.0/", true},
		{"unspecified-v6", "http://[::]/x", true},
		{"localhost-name", "http://localhost/", true},
		{"localhost-name-with-port", "http://localhost:3000/", true},
		{"localhost-bare", "localhost", true},
		{"localhost-trailing-dot", "http://localhost./", true},
		{"localhost-uppercase", "HTTP://LOCALHOST/", true},
		{"trailing-dot-ipv4", "http://127.0.0.1./", true},
		{"v4-mapped-loopback", "http://[::ffff:127.0.0.1]/x", true},

		{"public-v4", "https://example.com/", false},
		{"public-dns", "http://example.com:8080/", false},
		{"just-below-127", "http://126.255.255.255/", false},
		{"just-above-127", "http://128.0.0.0/", false},
		{"ipv6-loopback-neighbour", "http://[::2]/x", false},
		{"not-the-name", "http://localhost.example.com/", false},
		{"localhost-in-path", "http://example.com/localhost", false},
		{"private-is-not-loopback", "http://10.0.0.1/", false},
		{"metadata-is-not-loopback", "http://169.254.169.254/", false},

		{"empty", "", false},
		{"path-only", "/debug", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLoopback(tc.raw); got != tc.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsCloudMetadata pins the AWS/GCP/Azure link-local metadata address and
// the GCP metadata hostname, and — the reason hostOf exists — the host:port
// form that IsMetadataHost on its own will not match.
func TestIsCloudMetadata(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"aws-ip", "http://169.254.169.254/latest/meta-data/", true},
		{"aws-ip-bare", "169.254.169.254", true},
		{"aws-ip-with-port", "http://169.254.169.254:80/latest/", true},
		{"aws-ip-v6-path", "http://[::ffff:169.254.169.254]/latest/", true},
		{"gcp-hostname", "http://metadata.google.internal/", true},
		{"gcp-hostname-bare", "metadata.google.internal", true},
		{"gcp-hostname-trailing-dot", "http://metadata.google.internal./", true},
		{"gcp-hostname-uppercase", "HTTP://METADATA.GOOGLE.INTERNAL/", true},

		// TRAP 1, the SSRF bypass. Passing u.Host here — instead of
		// u.Hostname() — makes netguard.IsMetadataHost return false and the
		// metadata host is classified as an ordinary public host.
		{"gcp-hostname-with-port", "http://metadata.google.internal:8080/", true},
		{"gcp-hostname-with-port-uppercase", "HTTP://METADATA.GOOGLE.INTERNAL:8080/x", true},

		{"just-below-link-local", "http://169.253.0.1/", false},
		{"just-above-link-local", "http://169.255.0.1/", false},
		{"other-link-local", "http://169.254.1.1/", false},
		{"metadata-prefix-attack", "http://xmetadata.google.internal/", false},
		{"metadata-suffix-attack", "http://metadata.google.internal.evil.com/", false},

		// PARSED, so a metadata IP in a path is not a metadata host. recon's
		// cloudMetadataRE text-matches the IP anywhere, so this row is a real
		// Task 4 delta and is CHANGELOG'd there.
		{"DRIFT-metadata-in-path", "http://foo.com/169.254.169.254/x", false},
		{"public-ip", "https://8.8.8.8/", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCloudMetadata(tc.raw); got != tc.want {
				t.Errorf("IsCloudMetadata(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsInternalHost pins the union of recon's internalHostRE and
// k8sServiceRE. Either regex alone drops real matches: "svc.cluster" only
// matches the k8s one, "api.corp.example.com" only the host one.
//
// RAW-TEXT, so the path-position rows below are deliberate: this predicate
// reproduces recon's regexes exactly, and host-parsing it would have made
// them stop matching for no gain in netguard reuse.
func TestIsInternalHost(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"internal-suffix", "http://foo.internal/", true},
		{"internal-suffix-bare", "foo.internal", true},
		{"corp-suffix", "api.corp.example.com", true},
		{"corp-suffix-url", "http://api.corp.example.com/x", true},
		{"dot-local", "db.local", true},
		{"dot-local-url", "http://db.local/x", true},
		{"k8s-cluster", "svc.cluster", true},
		{"k8s-svc", "a.b.svc", true},
		{"k8s-svc-simple", "http://a.b.svc/x", true},
		{"k8s-local", "http://foo.bar.local/x", true},
		{"k8s-internal", "http://a.b.c.internal/x", true},
		{"trailing-dot-internal", "http://foo.internal./", true},
		{"uppercase", "http://FOO.INTERNAL/", true},

		{"public-host", "https://example.com/", false},
		{"public-host-with-path", "https://example.com/internal", false},
		{"internal-token-in-path", "https://example.com/internal/", false},
		{"empty", "", false},

		// These match today (recon's k8sServiceRE text-matches the whole URL)
		// and must keep matching. They were DRIFT rows while this predicate
		// was host-scoped; raw-text matching removed the drift class.
		{"internal-as-path-label", "https://example.com/x.internal/y", true},
		{"svc-in-path", "https://example.com/a.b.svc/x", true},
		{"local-in-path", "https://example.com/x.local", true},
		{"metadata-name-in-path", "http://foo.com/metadata.google.internal/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInternalHost(tc.raw); got != tc.want {
				t.Errorf("IsInternalHost(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsInternalPath pins the 13-token union of recon's internalRE and
// internalPathRE, with the \b|/|$ trailing rule.
//
// The token list is the union because neither regex alone is sufficient:
// "/intranet" and "/corp" come only from internalRE, "/debug" and "/admin"
// only from internalPathRE. The trailing group is \b|/|$ rather than /|$,
// because a bare "/corp" and "/intranet" are real matches that /|$ drops.
//
// This predicate matches the raw string, not the parsed path: recon is handed
// a URL string and "/internal" appears in it regardless of host.
func TestIsInternalPath(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		// internalRE-only tokens: these need the \b terminator.
		{"intranet-bare", "/intranet", true},
		{"intranet-path", "/intranet/x", true},
		{"corp-bare", "/corp", true},
		{"corp-path", "/corp/x", true},
		{"corp-in-url", "http://x.com/corp", true},
		{"internal-bare", "/internal", true},
		{"internal-path", "/internal/x", true},
		{"private", "/private", true},
		// internalPathRE-only tokens.
		{"admin-bare", "/admin", true},
		{"staging", "/staging/api", true},
		{"debug", "/debug", true},
		{"trace", "/trace", true},
		{"dev", "/dev", true},
		{"test", "/test", true},
		{"sandbox", "/sandbox/x", true},
		{"legacy", "/legacy", true},
		{"hidden", "/hidden", true},
		// \b must not fire mid-token.
		{"admin-suffix-not-boundary", "/administrator", false},
		{"debug-suffix-not-boundary", "/debugger", false},
		{"test-suffix-not-boundary", "/testing", false},
		{"dev-suffix-not-boundary", "/development", false},
		// A token with no leading slash is not a path token.
		{"no-leading-slash", "internal/x", false},

		// The 13 tokens must NOT share one trailing rule. The four
		// internalRE tokens carry \b; the nine internalPathRE-only tokens
		// carry the stricter (?:/|$). Applying \b to all 13 over-matched
		// these five rows; applying (?:/|$) to all 13 would under-match the
		// three below. Both directions are pinned so neither regression can
		// return.
		{"strict-admin-before-query", "/admin?x=1", false},
		{"strict-debug-before-query", "/debug?a=b", false},
		{"strict-sandbox-before-dot", "/sandbox.json", false},
		{"strict-legacy-before-dot", "/legacy.tar", false},
		{"strict-trace-before-fragment", "/trace#x", false},
		{"loose-internal-before-hyphen", "/internal-api", true},
		{"loose-intranet-before-hyphen", "/intranet-tools", true},
		{"loose-corp-before-dot", "/corp.example.com", true},
		{"loose-private-before-hyphen", "/private-v2", true},

		{"public-path", "/api/v1/users", false},
		{"public-url", "https://example.com/api/users", false},
		{"empty", "", false},
		{"root", "/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInternalPath(tc.raw); got != tc.want {
				t.Errorf("IsInternalPath(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsSensitivePort pins the database/service port list.
//
// The \b terminator is load-bearing: without it ":33060" matches ":3306" and
// every long port in a URL becomes a finding.
func TestIsSensitivePort(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"mysql", "http://h:3306/", true},
		{"postgres", "redis://h:5432", true},
		{"redis-scheme", "redis://h:6379", true},
		{"mongo", "mongodb://h:27017/x", true},
		{"elasticsearch-http", "http://h:9200/_search", true},
		{"elasticsearch-transport", "http://h:9300/", true},
		{"memcached", "http://h:11211/", true},
		{"couchdb", "http://h:5984/_all_dbs", true},
		{"consul-http", "http://h:8500/v1/kv", true},
		{"consul-dns", "http://h:8600/v1/kv", true},
		{"vault", "http://h:8200/v1/sys/health", true},
		{"bare-port-only", ":5432", true},
		{"uppercase-scheme", "REDIS://h:6379", true},

		// The \b terminator. Without it every one of these is a finding.
		{"terminator-33060", "http://h:33060/", false},
		{"terminator-54321", "http://h:54321/", false},
		{"terminator-63790", "redis://h:63790", false},
		{"terminator-82001", "http://h:82001/", false},

		{"http-port", "http://h:8080/", false},
		{"https-port", "https://example.com:443/x", false},
		{"public-port", "http://h:3000/", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSensitivePort(tc.raw); got != tc.want {
				t.Errorf("IsSensitivePort(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsPrivateIPIsNarrowerThanIsBlockedIP is the guard for the trap that
// internalurl.IsPrivateHost must not be built on netguard.IsBlockedIP.
//
// IsBlockedIP is deliberately wide — it must never be fetched, so it covers
// private AND loopback AND link-local AND unspecified. IsPrivateHost needs the
// narrow RFC 1918 answer, because recon classifies those other ranges under
// different categories. If this test ever fails, IsPrivateHost has widened.
func TestIsPrivateIPIsNarrowerThanIsBlockedIP(t *testing.T) {
	private := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.0", "172.31.255.255",
		"192.168.0.0", "192.168.255.255",
	}
	notPrivate := []string{
		"8.8.8.8",
		"127.0.0.1",       // loopback
		"127.255.255.255", // loopback
		"::1",             // loopback
		"169.254.169.254", // link-local (metadata)
		"fe80::1",         // link-local
		"0.0.0.0",         // unspecified
		"::",              // unspecified
		"172.15.0.1",      // just below 172.16/12
		"172.32.0.1",      // just above 172.16/12
		"192.169.0.1",     // just above 192.168/16
	}
	for _, a := range private {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", a)
		}
		if !netguard.IsPrivateIP(ip) {
			t.Errorf("netguard.IsPrivateIP(%s) = false, want true", a)
		}
		if !netguard.IsBlockedIP(ip) {
			t.Errorf("netguard.IsBlockedIP(%s) = false, want true (invariant)", a)
		}
	}
	for _, a := range notPrivate {
		ip := net.ParseIP(a)
		if ip == nil {
			t.Fatalf("test bug: %q did not parse", a)
		}
		if netguard.IsPrivateIP(ip) {
			t.Errorf("netguard.IsPrivateIP(%s) = true, want false", a)
		}
	}
	if netguard.IsPrivateIP(nil) {
		t.Error("netguard.IsPrivateIP(nil) = true, want false")
	}
}
