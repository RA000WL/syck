package netguard

import (
	"net"
	"testing"
)

// TestAllowFetchTable pins every behavior the AllowFetch doc comment claims:
// the deny list, the CIDR boundaries around each entry, trailing-dot and
// case-insensitive tolerance for the metadata hostname, the literal-IP-only
// (no DNS resolution) policy, and the empty-host / unparseable handling.
//
// This table was written and verified against the pre-extraction code, before
// IsBlockedIP / IsMetadataHost existed. Do not relax a case to match a code
// change: a failing case is a security regression, not a stale expectation.
func TestAllowFetchTable(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		// --- deny: private RFC1918, loopback, link-local, unspecified literals
		{"deny/10.0.0.1", "http://10.0.0.1/", false},
		{"deny/172.16.5.4:8080", "http://172.16.5.4:8080/x", false},
		{"deny/192.168.1.1", "http://192.168.1.1/admin", false},
		{"deny/169.254.169.254", "http://169.254.169.254/latest/meta-data/", false},
		{"deny/127.0.0.1:8080", "http://127.0.0.1:8080/x", false},
		{"deny/0.0.0.0", "http://0.0.0.0/x", false},
		{"deny/::1", "http://[::1]/x", false},
		{"deny/::", "http://[::]/x", false},

		// --- deny: metadata hostname, including the doc comment's normalization claims
		{"deny/metadata.google.internal", "http://metadata.google.internal/", false},
		{"deny/metadata-trailing-dot", "http://metadata.google.internal./", false},
		{"deny/metadata-uppercase", "http://METADATA.GOOGLE.INTERNAL/", false},
		{"deny/metadata-mixed-case-trailing-dot", "http://Metadata.Google.Internal./", false},

		// --- deny: the metadata hostname is denied *with a port* too. AllowFetch
		// passes u.Hostname() to IsMetadataHost, which strips the port, so an
		// explicit port cannot smuggle the metadata host past the denylist. The
		// IsMetadataHost contract is "bare hostname"; these rows are what make
		// that contract observable at the URL level.
		{"deny/metadata-with-port", "http://metadata.google.internal:8080/", false},
		{"deny/metadata-uppercase-with-port", "HTTP://METADATA.GOOGLE.INTERNAL:8080/x", false},

		// --- deny: 172.16.0.0/12 boundaries (first and last address are inside)
		{"deny/172.16.0.0", "http://172.16.0.0/", false},
		{"deny/172.31.255.255", "http://172.31.255.255/", false},

		// --- deny: 192.168.0.0/16 and 169.254.0.0/16 boundaries
		{"deny/192.168.0.0", "http://192.168.0.0/", false},
		{"deny/169.254.0.0", "http://169.254.0.0/", false},
		{"deny/169.254.255.255", "http://169.254.255.255/", false},

		// --- deny: IPv6 link-local (fe80::/10) and a v4-mapped literal, which
		// still resolves to the 10/8 address and must not slip through.
		{"deny/fe80::1", "http://[fe80::1]/x", false},
		{"deny/v4-mapped-10.0.0.1", "http://[::ffff:10.0.0.1]/x", false},

		// --- deny: unparseable absolute URLs, and absolute-looking URLs with
		// an empty host (malformed, not a harmless relative).
		{"deny/unparseable-space-in-host", "http://exa mple.com/", false},
		{"deny/unparseable-missing-scheme", "://nope", false},
		{"deny/absolute-empty-host", "http://", false},
		{"deny/absolute-empty-host-uppercase-scheme", "HTTP://", false},
		{"deny/protocol-relative-empty-host", "//", false},

		// --- allow: DNS names. Batch 1 does no DNS resolution, so every
		// hostname is allowed unless it is the metadata hostname.
		{"allow/example.com", "https://example.com/", true},
		{"allow/dns-name-trailing-dot", "http://example.com./", true},
		{"allow/dns-name-uppercase", "http://EXAMPLE.COM/", true},
		{"allow/protocol-relative", "//example.com/x", true},

		// --- allow: localhost is DELIBERATELY allowed. Batch 1 checks literal
		// IPs only, so "localhost" is just a DNS name as far as this gate is
		// concerned. This is intentional; do not "fix" it into a deny.
		{"allow/localhost", "http://localhost/", true},

		// --- allow: public IPs
		{"allow/8.8.8.8", "https://8.8.8.8/", true},
		{"allow/1.1.1.1", "http://1.1.1.1/", true},
		{"allow/public-v6", "http://[2606:4700:4700::1111]/x", true},

		// --- allow: 172.16.0.0/12 boundaries just outside the range
		{"allow/172.15.0.1", "http://172.15.0.1/", true},
		{"allow/172.32.0.1", "http://172.32.0.1/", true},

		// --- allow: 192.168.0.0/16 boundaries just outside the range
		{"allow/192.167.0.1", "http://192.167.0.1/", true},
		{"allow/192.169.0.1", "http://192.169.0.1/", true},

		// --- allow: 169.254.0.0/16 boundaries just outside the range
		{"allow/169.253.0.1", "http://169.253.0.1/", true},
		{"allow/169.255.0.1", "http://169.255.0.1/", true},

		// --- allow: relative references have no host to gate
		{"allow/absolute-path", "/sitemap.xml", true},
		{"allow/bare-relative", "sitemap.xml", true},
		// AllowFetch("") is true because the empty input lands in the
		// empty-host branch: url.Parse("") succeeds with an empty Hostname(),
		// and the raw URL contains neither "://" nor a leading "//", so the
		// "looked absolute but has no host" malformed case does not apply.
		// Nothing is being fetched, so there is no target to gate.
		{"allow/empty-string", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AllowFetch(tc.raw); got != tc.want {
				t.Errorf("AllowFetch(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestIsBlockedIP exercises IsBlockedIP directly, one address at a time, so a
// later "widen the ranges" edit cannot silently regress through AllowFetch.
// Every range is pinned symmetrically: its first address, its last address, and
// the address immediately below and immediately above it. Do not relax a case
// to match a code change: a failing case is a security regression, not a
// stale expectation.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		name string
		addr string // "" means a nil net.IP
		want bool
	}{
		// A nil net.IP is not a literal IP, so there is nothing to block.
		{"nil ip", "", false},

		// --- 10.0.0.0/8
		{"10/8 first address", "10.0.0.0", true},
		{"10/8 last address", "10.255.255.255", true},
		{"10/8 just below", "9.255.255.255", false},
		{"10/8 just above", "11.0.0.0", false},

		// --- 172.16.0.0/12
		{"172.16/12 first address", "172.16.0.0", true},
		{"172.16/12 last address", "172.31.255.255", true},
		{"172.16/12 just below", "172.15.255.255", false},
		{"172.16/12 just above", "172.32.0.0", false},

		// --- 192.168.0.0/16
		{"192.168/16 first address", "192.168.0.0", true},
		{"192.168/16 last address", "192.168.255.255", true},
		{"192.168/16 just below", "192.167.255.255", false},
		{"192.168/16 just above", "192.169.0.0", false},

		// --- 127.0.0.0/8 (reached via IsLoopback as well as the CIDR)
		{"127/8 first address", "127.0.0.0", true},
		{"127/8 last address", "127.255.255.255", true},
		{"127/8 just below", "126.255.255.255", false},
		{"127/8 just above", "128.0.0.0", false},

		// --- 169.254.0.0/16 (reached via IsLinkLocalUnicast as well as the CIDR)
		{"169.254/16 first address", "169.254.0.0", true},
		{"169.254/16 last address", "169.254.255.255", true},
		{"169.254/16 just below", "169.253.255.255", false},
		{"169.254/16 just above", "169.255.0.0", false},

		// --- fe80::/10 (IPv6 link-local). fe80:: is the first address and
		// febf:ffff:...:ffff the last; fe7f:ffff:...:ffff is below the range and
		// fec0:: is above it.
		{"fe80::/10 first address", "fe80::", true},
		{"fe80::/10 last address", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"fe80::/10 just below", "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"fe80::/10 just above", "fec0::1", false},

		// --- ::1 (IPv6 loopback), pinned against its immediate neighbor
		{"::1", "::1", true},
		{"just above ::1", "::2", false},

		// --- the unspecified address, in either family
		{"unspecified 0.0.0.0", "0.0.0.0", true},
		{"unspecified ::", "::", true},
		{"just above unspecified v4", "0.0.0.1", false},

		// --- a v4-mapped literal resolves to the IPv4 address and must still
		// be matched against the IPv4 ranges
		{"v4-mapped private", "::ffff:10.0.0.1", true},
		{"v4-mapped public", "::ffff:8.8.8.8", false},

		// --- routable addresses are not blocked
		{"public v4", "8.8.8.8", false},
		{"public v6", "2606:4700:4700::1111", false},

		// --- IPv6 ranges that are NOT in the blocklist. fec0::/10 (deprecated
		// site-local) sits just above fe80::/10 and fc00::/7 (ULA) sits below it;
		// neither is covered, so a reader must not assume "private IPv6" is
		// blocked. This mirrors the IPv4 side, where CGNAT 100.64.0.0/10 is also
		// not in the list.
		{"fec0::1 deprecated site-local is not blocked", "fec0::1", false},
		{"fc00::1 ULA is not blocked", "fc00::1", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ip net.IP
			if tc.addr != "" {
				ip = net.ParseIP(tc.addr)
				if ip == nil {
					t.Fatalf("test bug: %q is not a valid IP literal", tc.addr)
				}
			}
			if got := IsBlockedIP(ip); got != tc.want {
				t.Errorf("IsBlockedIP(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestIsMetadataHost exercises the hostname denylist directly, pinning the
// parameter contract: host must be a BARE hostname as produced by
// url.URL.Hostname(). A "host:port" pair must not match, because the port is
// the caller's job to strip. Do not relax a case to match a code change: a
// failing case is a security regression, not a stale expectation.
func TestIsMetadataHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		// The one true positive, plus the two documented normalizations.
		{"exact match", "metadata.google.internal", true},
		{"trailing dot", "metadata.google.internal.", true},
		{"uppercase", "METADATA.GOOGLE.INTERNAL", true},
		{"mixed case with trailing dot", "Metadata.Google.Internal.", true},

		// A host:port pair is NOT a bare hostname and must not match. A caller
		// passing url.URL.Host instead of url.URL.Hostname() would silently
		// allow the metadata host, which is why these are pinned.
		{"host with port", "metadata.google.internal:8080", false},
		{"uppercase host with port", "METADATA.GOOGLE.INTERNAL:8080", false},

		// Other hostnames are not the metadata host.
		{"unrelated hostname", "example.com", false},
		{"unrelated hostname with trailing dot", "example.com.", false},
		{"localhost", "localhost", false},
		{"empty host", "", false},
		{"bare dot", ".", false},

		// Neighbouring hostnames that merely resemble the metadata host.
		{"prefix attack", "xmetadata.google.internal", false},
		{"suffix attack", "metadata.google.internal.evil.com", false},
		// Exactly one trailing dot is trimmed, so a doubled dot does not match.
		// That is not a bypass: a doubled-dot label is not a resolvable hostname.
		{"double trailing dot", "metadata.google.internal..", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMetadataHost(tc.host); got != tc.want {
				t.Errorf("IsMetadataHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
