package netguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
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

		// ---------------------------------------------------------------------
		// Legacy inet_aton IPv4 forms. net.ParseIP rejects every one of these,
		// so before Batch 6 Task 3 they fell through to the DNS-name branch and
		// were ALLOWED — including four spellings of 127.0.0.1.
		// ---------------------------------------------------------------------
		{"deny/legacy-int-127.0.0.1", "http://2130706433/", false},
		{"deny/legacy-two-part-127.0.0.1", "http://127.1/", false},
		{"deny/legacy-leading-zero-octal", "http://010.0.0.1/", false},
		{"deny/legacy-hex-first-part", "http://0x7f.0.0.1/", false},
		{"deny/legacy-hex-int-127.0.0.1", "http://0x7f000001/", false},

		// The other three blocked ranges, in legacy spellings, so the fix is not
		// a loopback-only special case. "10.1" is 10.0.0.1, "169.254.0" is
		// 169.254.0.0 (link-local, i.e. the AWS/GCP metadata neighborhood),
		// "192.168.1" is 192.168.0.1 and "172.16.0" is 172.16.0.0. Each is
		// written in 3-part form because that is the only short form that lands
		// in the range: in 2-part form "169.254" is 169.0.0.254 and "172.16"
		// is 172.0.0.16, both public.
		{"deny/legacy-10.0.0.1", "http://10.1/", false},
		{"deny/legacy-169.254.0.0", "http://169.254.0/", false},
		{"deny/legacy-192.168.0.1", "http://192.168.1/", false},
		{"deny/legacy-172.16.0.0", "http://172.16.0/", false},
		{"deny/legacy-hex-10.0.0.1", "http://0xa.0.0.1/", false},
		{"deny/legacy-hex-int-192.168.1.1", "http://3232235777/", false},
		{"deny/legacy-hex-int-c0a80001", "http://0xc0a80001/", false},
		{"deny/legacy-three-part-127.1.0.1", "http://127.1.1/", false},

		// Deny on ambiguity: a host made only of digits, dots and a hex
		// prefix that does not resolve to a valid IPv4 address is far more
		// likely an evasion attempt than a real target. This includes a
		// trailing-dot "FQDN" spelling of an address — net.ParseIP rejects
		// "192.168.1.1." too, so it was allowed before this fix.
		{"deny/legacy-ambiguous-octet-overflow", "http://999.1.1.1/", false},
		{"deny/legacy-ambiguous-too-many-parts", "http://1.2.3.4.5/", false},
		{"deny/legacy-ambiguous-trailing-dot", "http://192.168.1.1./", false},
		{"deny/legacy-ambiguous-leading-zero-part", "http://09.0.0.1/", false},
		{"deny/legacy-ambiguous-overflows-uint32", "http://4294967296/", false},
		// A host of nothing but dots is address-shaped but denotes nothing, so
		// it is denied on ambiguity rather than passed off as a name.
		{"deny/legacy-ambiguous-bare-dot", "http://./", false},
		{"deny/legacy-ambiguous-double-dot", "http://..//", false},

		// --- IPv6 zone identifiers. url.URL.Hostname() percent-decodes %25,
		// so "[fe80::1%25eth0]" arrives as the host "fe80::1%eth0";
		// net.ParseIP rejects the zone, so it used to be allowed. The zone
		// must be stripped and the SAME checks run — not waived.
		{"deny/v6-zone-fe80-link-local", "http://[fe80::1%25eth0]/x", false},
		{"deny/v6-zone-loopback", "http://[::1%25lo]/x", false},
		{"deny/v6-zone-unspecified", "http://[::%25lo]/x", false},
		{"deny/v6-zone-v4-mapped-private", "http://[::ffff:10.0.0.1%25eth0]/x", false},

		// --- allow: legacy forms that denote PUBLIC addresses. These are the
		// control for the whole change: they prove the parser computes the
		// address and runs it through IsBlockedIP rather than blanket-denying
		// dotted numerics. If any of these flipped to deny, the fix would be
		// over-broad; if a bypass above were implemented by blanket-denying,
		// they would be the first casualties.
		// 134744072 == 0x08080808 == 8.8.8.8, 0x08080808 is the same address
		// in hex, and 1.2.3 is 1.2.0.3 (the third part fills two bytes).
		{"allow/legacy-int-8.8.8.8", "http://134744072/", true},
		{"allow/legacy-hex-int-8.8.8.8", "http://0x08080808/", true},
		{"allow/legacy-three-part-1.2.0.3", "http://1.2.3/", true},
		{"allow/legacy-two-part-8.8.8.0", "http://8.8.2048/", true},
		{"allow/legacy-hex-final-part", "http://8.8.0x800/", true},
		{"allow/legacy-int-192.0.2.1", "http://3221225985/", true},

		// --- allow: a zoned PUBLIC IPv6 address. Stripping the zone must not
		// turn into "anything with a zone is denied" any more than it turns
		// into "anything with a zone is public".
		{"allow/v6-zone-public", "http://[2606:4700:4700::1111%25eth0]/x", true},
		{"allow/v6-zone-fec0-site-local", "http://[fec0::1%25eth0]/x", true},

		// --- allow: DNS names are unaffected by the legacy parser. The shape
		// test admits only digits, dots, and an x immediately preceded by a 0,
		// so a name can never be reclassified as an address. These pin that.
		{"allow/hostname-with-x", "http://x.example.com/", true},
		{"allow/hostname-letters-in-first-label", "http://2a.example.com/", true},
		{"allow/hostname-numeric-label", "http://1.example.com/", true},
		{"allow/hostname-locale-dots", "http://xn--bcher-kva.example/", true},
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

// TestPrivateIPImpliesBlocked pins the invariant that lets IsBlockedIP
// delegate the RFC 1918 test to IsPrivateIP instead of re-listing the three
// ranges: anything IsPrivateIP accepts is also blocked from being fetched.
//
// This test lives here, in the package that owns the list, rather than only in
// internalurl's tests. It sweeps the boundaries of all three ranges plus a
// band of public addresses, so adding a range to IsPrivateIP without adding
// it to IsBlockedIP's reachable set fails HERE instead of quietly making
// AllowFetch allow a range internalurl classifies as private.
func TestPrivateIPImpliesBlocked(t *testing.T) {
	addrs := []string{
		// 10/8 boundaries, plus the v4-mapped forms the stdlib normalizes.
		"10.0.0.0", "10.255.255.255", "9.255.255.255", "11.0.0.0",
		"::ffff:10.0.0.0", "::ffff:10.255.255.255",
		// 172.16/12 boundaries.
		"172.16.0.0", "172.31.255.255", "172.15.255.255", "172.32.0.0",
		"::ffff:172.16.0.0", "::ffff:172.31.255.255",
		// 192.168/16 boundaries.
		"192.168.0.0", "192.168.255.255", "192.167.255.255", "192.169.0.0",
		"::ffff:192.168.0.0", "::ffff:192.168.255.255",
	}
	// Public and non-private controls, so the sweep also proves the test is
	// not trivially passing. The CGNAT 100.64/10 boundaries are included
	// specifically: it is the range most likely to be added to IsPrivateIP
	// next, and it is NOT currently in either list — the invariant test then
	// fails if it is added to IsPrivateIP without IsBlockedIP reaching it.
	addrs = append(addrs, "8.8.8.8", "1.1.1.1", "172.16.0.1", "192.168.1.1",
		"10.1.2.3", "127.0.0.1", "169.254.169.254", "fe80::1", "::1", "0.0.0.0",
		"100.64.0.0", "100.127.255.255", "100.63.255.255", "100.128.0.0",
		"100.64.0.1")

	for _, s := range addrs {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP literal", s)
		}
		if IsPrivateIP(ip) && !IsBlockedIP(ip) {
			t.Errorf("IsPrivateIP(%q) = true but IsBlockedIP(%q) = false: "+
				"the private CIDR list must not be re-listed in IsBlockedIP",
				s, s)
		}
	}

	if IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) = true, want false: a nil net.IP is not a literal IP")
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

// TestParseLegacyIPv4 pins what each legacy spelling RESOLVES TO, not just
// whether it is allowed. This is the direct evidence that the parser computes
// an address: every "want" here is the real inet_aton meaning of the form, so
// a future edit that replaced the conversion with a blanket deny of dotted
// numerics would fail these rows instead of quietly passing the AllowFetch
// table's allow cases for the wrong reason.
func TestParseLegacyIPv4(t *testing.T) {
	cases := []struct {
		host string
		want string // "" means "must not parse"
	}{
		// --- 1-part: the whole 32-bit address, decimal or hex
		{"2130706433", "127.0.0.1"},
		{"3232235777", "192.168.1.1"},
		{"134744072", "8.8.8.8"},
		{"3221225985", "192.0.2.1"},
		{"0x7f000001", "127.0.0.1"},
		{"0x08080808", "8.8.8.8"},

		// --- 2-part: the second part fills the low 24 bits
		{"127.1", "127.0.0.1"},
		{"10.1", "10.0.0.1"},
		{"8.8.2048", "8.8.8.0"},
		// "169.254" is 169.0.0.254, NOT 169.254.0.0: only 3- and 4-part
		// forms can spell a 169.254 address compactly.
		{"169.254", "169.0.0.254"},

		// --- 3-part: the third part fills the low 16 bits
		{"127.1.1", "127.1.0.1"},
		{"1.2.3", "1.2.0.3"},
		{"192.168.1", "192.168.0.1"},
		{"169.254.0", "169.254.0.0"},
		{"172.16.0", "172.16.0.0"},

		// --- 4-part with a hex or hex-low byte
		{"0x7f.0.0.1", "127.0.0.1"},
		{"0xa.0.0.1", "10.0.0.1"},
		{"0xc0a80001", "192.168.0.1"},
		{"8.8.0x800", "8.8.8.0"},
		{"8.8.8.0", "8.8.8.0"},

		// --- must NOT parse: ambiguous or malformed numerics
		{"", ""},
		{"010.0.0.1", ""},    // octal 8.0.0.1 vs decimal 10.0.0.1
		{"09.0.0.1", ""},     // leading zero
		{"00.0.0.1", ""},     // leading zero
		{"999.1.1.1", ""},    // octet overflow
		{"1.2.3.4.5", ""},    // too many parts
		{"192.168.1.1.", ""}, // trailing dot: FQDN spelling, not inet_aton
		{"4294967296", ""},   // one past 2^32-1
		{"1.2.3.x", ""},      // not a digit
		{"0x", ""},           // prefix with no digits
		{"0xzz", ""},         // not hex
		{"..", ""},           // no digits at all
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			ip, ok := parseLegacyIPv4(tc.host)
			if tc.want == "" {
				if ok {
					t.Errorf("parseLegacyIPv4(%q) = %v, want no parse", tc.host, ip)
				}
				return
			}
			if !ok {
				t.Fatalf("parseLegacyIPv4(%q) did not parse, want %s", tc.host, tc.want)
			}
			if got := ip.String(); got != tc.want {
				t.Errorf("parseLegacyIPv4(%q) = %s, want %s", tc.host, got, tc.want)
			}
		})
	}
}

// TestLegacyIPv4CandidateRejectsNames is the safety property behind
// "never classify a DNS name as an IP": legacyIPv4Candidate is the gate that
// keeps the legacy parser from ever running on a hostname, so every name here
// must be rejected. If any of these became a candidate, a real target's name
// would be reinterpreted as a raw address.
func TestLegacyIPv4CandidateRejectsNames(t *testing.T) {
	names := []string{
		"localhost",
		"example.com",
		"example.com.",
		"EXAMPLE.COM",
		"a.b.c.d.example.com",
		"2a.example.com",        // alphanumeric label
		"x.example.com",         // an x not preceded by a 0
		"0xexample.com",         // "0x" then letters that are not hex
		"xn--bcher-kva.example", // punycode label
		"host.example.co.uk",
		"127.0.0.1.nip.io", // a name that embeds an address
		"metadata.google.internal",
		"2130706433.example.com",
		"0xdeadbeef.example",
		"9gag.com",
		"x0x1.com",
	}
	for _, h := range names {
		if legacyIPv4Candidate(h) {
			t.Errorf("legacyIPv4Candidate(%q) = true, want false: a DNS name must "+
				"never be treated as an address", h)
		}
	}

	// A dot-only host is deliberately NOT in the list above: it is not a name,
	// it is address-shaped and denotes nothing. legacyIPv4Candidate accepts it
	// so that parseLegacyIPv4 rejects it and AllowFetch denies it on ambiguity.
	// Pinned here because the accepting half of that split is otherwise
	// invisible.
	for _, h := range []string{".", ".."} {
		if !legacyIPv4Candidate(h) {
			t.Errorf("legacyIPv4Candidate(%q) = false, want true: a dot-only host "+
				"must reach the parser so it is denied as ambiguous", h)
		}
		if _, ok := parseLegacyIPv4(h); ok {
			t.Errorf("parseLegacyIPv4(%q) parsed, want no parse", h)
		}
	}

	// And the shapes that must be accepted, so the test above is not vacuous.
	for _, h := range []string{"2130706433", "127.1", "1.2.3", "127.0.0.1",
		"0x7f.0.0.1", "0x08080808", "192.168.1.1.", "999.1.1.1", "1.2.3.4.5"} {
		if !legacyIPv4Candidate(h) {
			t.Errorf("legacyIPv4Candidate(%q) = false, want true", h)
		}
	}
}

// allowFetchBatch1 is the gate as it behaved before Batch 6 Task 3: net.ParseIP
// or nothing. It is reproduced here as an oracle so the "strictly tighter"
// property is checkable rather than asserted.
func allowFetchBatch1(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		lower := strings.ToLower(rawURL)
		if strings.Contains(lower, "://") || strings.HasPrefix(lower, "//") {
			return false
		}
		return true
	}
	if IsMetadataHost(host) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !IsBlockedIP(ip)
	}
	return true
}

// TestAllowFetchNeverLoosens pins the property that mattered most for this
// change: for every input, anything Batch 1 denied is still denied. A security
// gate that gains an evasion but loses a block is a net regression even if the
// new table passes, so the implication is checked directly over a corpus built
// from every blocked range's boundaries and their legacy spellings.
//
// A deny -> allow flip here is a critical regression.
func TestAllowFetchNeverLoosens(t *testing.T) {
	v4 := []string{
		// inside every blocked range
		"10.0.0.0", "10.0.0.1", "10.255.255.255",
		"172.16.0.0", "172.16.0.1", "172.31.255.255",
		"192.168.0.0", "192.168.0.1", "192.168.255.255",
		"127.0.0.0", "127.0.0.1", "127.255.255.255",
		"169.254.0.0", "169.254.169.254", "169.254.255.255",
		"0.0.0.0",
		// just outside each range, to catch an off-by-one that starts denying
		// public neighbours
		"9.255.255.255", "11.0.0.0",
		"172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0",
		"126.255.255.255", "128.0.0.0",
		"169.253.255.255", "169.255.0.0",
		"0.0.0.1",
		// public
		"8.8.8.8", "1.1.1.1", "192.0.2.1",
	}
	hosts := append([]string{}, v4...)
	for _, s := range v4 {
		n := binary.BigEndian.Uint32(net.ParseIP(s).To4())
		// 1-part integer and hex spellings
		hosts = append(hosts, fmt.Sprint(n), fmt.Sprintf("0x%x", n))
		// 2- and 3-part spellings, plus a trailing-dot FQDN spelling
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			hosts = append(hosts, parts[0]+"."+parts[1]+"."+parts[2],
				parts[0]+"."+parts[1], s+".")
		}
	}
	hosts = append(hosts,
		"::1", "::", "fe80::1", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"::ffff:10.0.0.1", "::ffff:8.8.8.8",
		"2606:4700:4700::1111", "fec0::1", "fc00::1",
		"fe80::1%eth0", "::1%lo", "2606:4700:4700::1111%eth0",
		"example.com", "localhost", "metadata.google.internal",
		"2130706433", "127.1", "010.0.0.1", "0x7f.0.0.1", "1.2.3", "134744072",
		"", "/sitemap.xml", "sitemap.xml", "http://", "//example.com/x",
	)

	for _, h := range hosts {
		raw := "http://" + h + "/"
		if strings.Contains(h, ":") || strings.Contains(h, "%") {
			raw = "http://[" + h + "]/"
		}
		before, after := allowFetchBatch1(raw), AllowFetch(raw)
		if !before && after {
			t.Errorf("REGRESSION: AllowFetch(%q) = true but Batch 1 denied it "+
				"(the gate must only get tighter)", raw)
		}
	}

	// Anti-vacuity: the oracle must actually deny something across every
	// blocked family, or the implication loop above proves nothing. Checked per
	// family rather than as a raw count so that emptying one family fails here
	// instead of being masked by a large count from another.
	mustDeny := map[string]string{
		"10/8":           "http://10.0.0.1/",
		"172.16/12":      "http://172.16.0.1/",
		"192.168/16":     "http://192.168.0.1/",
		"127/8":          "http://127.0.0.1/",
		"169.254/16":     "http://169.254.169.254/",
		"unspecified":    "http://0.0.0.0/",
		"fe80::/10":      "http://[fe80::1]/",
		"::1":            "http://[::1]/",
		"metadata host":  "http://metadata.google.internal/",
		"empty absolute": "http://",
		"v4-mapped 10/8": "http://[::ffff:10.0.0.1]/",
	}
	for name, raw := range mustDeny {
		if allowFetchBatch1(raw) {
			t.Errorf("anti-vacuity: oracle %s should deny %q but allows it; "+
				"TestAllowFetchNeverLoosens would pass vacuously", name, raw)
		}
		if !contains(hosts, hostOf(raw)) {
			t.Errorf("anti-vacuity: corpus does not contain %q", raw)
		}
	}
	// The bypasses this change exists to close. Batch 1 allowed every one of
	// them; the current gate must deny them. This is the positive evidence that
	// the change is not merely tightening without effect — without it, a
	// mutation that broke the parser could still satisfy the implication loop.
	bypasses := map[string]string{
		"legacy int 127.0.0.1":     "http://2130706433/",
		"legacy 2-part 127.0.0.1":  "http://127.1/",
		"legacy leading-zero":      "http://010.0.0.1/",
		"legacy hex 127.0.0.1":     "http://0x7f.0.0.1/",
		"legacy hex int 10.0.0.1":  "http://0xa.0.0.1/",
		"legacy 2-part 10.0.0.1":   "http://10.1/",
		"legacy 3-part link-local": "http://169.254.0/",
		"v6 zone link-local":       "http://[fe80::1%25eth0]/",
		"v6 zone loopback":         "http://[::1%25lo]/",
	}
	for name, raw := range bypasses {
		if !allowFetchBatch1(raw) {
			t.Errorf("corpus bug: %s (%q) was already denied by Batch 1, so it "+
				"is not evidence of a closed bypass", name, raw)
		}
		if AllowFetch(raw) {
			t.Errorf("BYPASS STILL OPEN: AllowFetch(%q) = true; %s was reachable "+
				"before this change", raw, name)
		}
	}
	// Controls: inputs Batch 1 allowed that must still be allowed. These are
	// the other half of "strictly tighter" — the change must not have closed
	// the gate on legitimate targets either. If any flipped to deny, the fix
	// would be over-broad even though nothing above failed.
	mustAllow := map[string]string{
		"public 8.8.8.8":   "http://8.8.8.8/",
		"public v6":        "http://[2606:4700:4700::1111]/",
		"localhost":        "http://localhost/",
		"example.com":      "http://example.com/",
		"legacy 134744072": "http://134744072/",
		"legacy 1.2.3":     "http://1.2.3/",
		"zoned public v6":  "http://[2606:4700:4700::1111%25eth0]/",
	}
	for name, raw := range mustAllow {
		if !allowFetchBatch1(raw) {
			t.Errorf("anti-vacuity: oracle %s should allow %q but denies it", name, raw)
		}
		if !AllowFetch(raw) {
			t.Errorf("REGRESSION: AllowFetch(%q) = false; %s is a legitimate "+
				"target that Batch 1 allowed, and this change must only tighten "+
				"the gate", raw, name)
		}
		if !contains(hosts, hostOf(raw)) {
			t.Errorf("anti-vacuity: corpus does not contain %q", raw)
		}
	}
}

// hostOf returns the url host of raw, for corpus membership checks.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
