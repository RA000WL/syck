package netguard

import "testing"

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
