// Package netguard gates secondary fetches against SSRF to private ranges.
//
// Batch 1 performs literal-IP checks only: no DNS resolution. DNS hostnames
// are allowed; only literal IPs in private ranges and the well-known cloud
// metadata hostname are denied.
//
// Batch 6 Task 3 widened "literal" to cover the spellings net.ParseIP rejects
// but clients honour — legacy inet_aton IPv4 and IPv6 zone-scoped literals.
// The gate only ever got tighter: see literalIP and legacyIPv4Candidate.
package netguard

import (
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var (
	private10    = mustCIDR("10.0.0.0/8")
	private172   = mustCIDR("172.16.0.0/12")
	private192   = mustCIDR("192.168.0.0/16")
	loopbackV4   = mustCIDR("127.0.0.0/8")
	linkLocalV4  = mustCIDR("169.254.0.0/16")
	linkLocalV6  = mustCIDR("fe80::/10")
	metadataHost = "metadata.google.internal"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// IsMetadataHost reports whether host is the well-known GCP metadata
// hostname. The comparison is case-insensitive and a trailing dot is
// tolerated, so "METADATA.GOOGLE.INTERNAL." matches.
//
// host must be a bare hostname as produced by url.URL.Hostname(). A
// "host:port" pair will NOT match: the port is the caller's job to strip, and
// passing url.URL.Host here would silently fail to deny the metadata host.
func IsMetadataHost(host string) bool {
	return strings.ToLower(strings.TrimSuffix(host, ".")) == metadataHost
}

// IsPrivateIP reports whether ip is in one of the three RFC 1918 private
// ranges: 10/8, 172.16/12, 192.168/16. It excludes loopback, link-local, and
// the unspecified address, all of which IsBlockedIP covers.
//
// The split exists because the two questions are different. "Must this never
// be fetched?" is wide (IsBlockedIP). "Is this address a private-network
// host?" is narrow (IsPrivateIP), and it is what a surface classifier needs:
// a loopback URL is categorized as loopback, not as private, and conflating
// the two would change recon's output. A nil ip is reported as not private.
//
// This function owns the RFC 1918 membership list: IsBlockedIP delegates to
// it rather than iterating the three ranges again, so the list is written
// once. The invariant IsPrivateIP ⟹ IsBlockedIP is pinned by
// TestPrivateIPImpliesBlocked.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range []*net.IPNet{private10, private172, private192} {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlockedIP reports whether ip is in a range that must never be fetched:
// 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, fe80::/10, ::1, and the
// unspecified address (0.0.0.0 or ::, either family).
// Literal IPs only — callers must have already handled DNS names.
// A nil ip is not a literal IP and is reported as not blocked.
//
// The RFC 1918 membership test is delegated to IsPrivateIP rather than
// re-listed here. This is the only copy of that list in the package, so
// widening IsPrivateIP cannot leave AllowFetch quietly allowing what
// internalurl now classifies as private. See IsPrivateIP for the invariant
// and TestPrivateIPImpliesBlocked.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if IsPrivateIP(ip) {
		return true
	}
	for _, n := range []*net.IPNet{loopbackV4, linkLocalV4, linkLocalV6} {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() {
		// Covers 127.0.0.0/8 and ::1.
		return true
	}
	if ip.IsUnspecified() {
		// 0.0.0.0 (and ::): not routable, never a legitimate fetch target.
		return true
	}
	return ip.IsLinkLocalUnicast()
}

// AllowFetch reports whether rawURL is safe to fetch as a secondary resource
// (sitemap child, sourcemap, redirect target). It returns false for literal
// IPs in 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, link-local ranges,
// ::1, 0.0.0.0, and for the metadata.google.internal hostname (with or
// without trailing dot). Those literals are recognized in every spelling
// literalIP resolves, including the legacy inet_aton forms (2130706433,
// 127.1, 0x7f.0.0.1) and IPv6 zone-scoped literals (fe80::1%eth0).
//
// All other inputs (public IPs, DNS hostnames, unparseable-but-harmless
// relatives) return true, except unparseable absolute URLs which return false,
// and address-shaped hosts that resolve to no valid address — which are
// denied rather than assumed to be names.
func AllowFetch(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		// Relative URL or no host component: nothing to gate.
		// If the input looked absolute (had a scheme or // prefix) but the
		// host is empty, treat it as malformed and deny.
		lower := strings.ToLower(rawURL)
		if strings.Contains(lower, "://") || strings.HasPrefix(lower, "//") {
			return false
		}
		return true
	}

	// Hostname denylist (case-insensitive, trailing dot tolerated).
	if IsMetadataHost(host) {
		return false
	}

	// Literal-IP checks only (still no DNS resolution).
	//
	// literalIP deliberately looks wider than net.ParseIP: it also resolves the
	// legacy inet_aton spellings (2130706433, 127.1, 010.0.0.1, 0x7f.0.0.1) and
	// IPv6 zone-scoped literals (fe80::1%eth0), all of which net.ParseIP
	// rejects and which therefore used to fall through to the "it must be a
	// DNS name" branch and be allowed.
	ip, kind := literalIP(host)
	switch kind {
	case literalDNSName:
		return true
	case literalAmbiguous:
		// Deny on ambiguity: an all-numeric-and-dots host that resolves to no
		// valid address is far more likely an evasion attempt than a real
		// target.
		return false
	}
	return !IsBlockedIP(ip)
}

// literalKind classifies what literalIP found in a URL host.
type literalKind int

const (
	// literalDNSName: the host is not address-shaped, so it is a name to be
	// left alone (Batch 1 does no DNS resolution).
	literalDNSName literalKind = iota
	// literalAddress: ip is the address the host denotes.
	literalAddress
	// literalAmbiguous: the host is address-shaped but resolves to no valid
	// address, so it is denied rather than treated as a name.
	literalAmbiguous
)

// literalIP resolves a URL host to the IP address it denotes, for hosts that
// are addresses rather than names.
//
// net.ParseIP is tried first so every literal it already accepts behaves
// exactly as before. Two families of address-shaped host remain that it
// rejects, and both were bypasses:
//
//   - The legacy inet_aton forms — a bare 32-bit integer ("2130706433"), 2- or
//     3-part forms ("127.1", "1.2.3") and hex/leading-zero spellings
//     ("0x7f.0.0.1", "010.0.0.1"). Many clients accept these, so a client
//     told to fetch "http://0xa.0.0.1/" reaches 10.0.0.1.
//   - IPv6 zone-scoped literals. url.URL.Hostname() percent-decodes %25, so
//     "[fe80::1%25eth0]" arrives as the host "fe80::1%eth0"; the zone is
//     stripped and the SAME checks then run, so a zoned link-local address is
//     denied rather than treated as a name.
//
// A host that is neither is reported as a name, never as an address: see
// legacyIPv4Candidate for why no DNS name can reach the legacy parser.
func literalIP(host string) (net.IP, literalKind) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, literalAddress
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		// Strip the zone and re-run the same parse rather than waiving the
		// check. The remainder is re-tested for a legacy IPv4 shape below, so
		// "2130706433%foo" cannot use a zone to smuggle an address past.
		host = host[:i]
		if ip := net.ParseIP(host); ip != nil {
			return ip, literalAddress
		}
	}
	if !legacyIPv4Candidate(host) {
		return nil, literalDNSName
	}
	ip, ok := parseLegacyIPv4(host)
	if !ok {
		return nil, literalAmbiguous
	}
	return ip, literalAddress
}

// legacyIPv4Candidate reports whether host is shaped like a legacy
// inet_aton-style IPv4 literal: dot-separated parts, where every part is
// either empty (only a run of dots can produce one), all decimal digits, or a
// "0x" prefix followed by hex digits.
//
// That shape is incapable of matching a DNS name. A hostname needs an
// alphabetic character in some label other than a "0x"-prefixed one — its
// top-level domain — and a name made only of digits and dots would require an
// all-numeric top-level domain, which no registry delegates (RFC 3696 §2).
// This test is what keeps the legacy parser from reclassifying a name as an
// address; it deliberately runs before parseLegacyIPv4, which is stricter.
//
// Empty parts are tolerated here so that a trailing-dot spelling of an address
// ("192.168.1.1.") counts as address-shaped and is denied on ambiguity by
// parseLegacyIPv4, rather than passing as a name.
func legacyIPv4Candidate(host string) bool {
	if host == "" {
		return false
	}
	for _, p := range strings.Split(host, ".") {
		if p == "" {
			continue
		}
		if !isLegacyShapePart(p) {
			return false
		}
	}
	return true
}

// isLegacyShapePart reports whether p is shaped like one inet_aton
// component: decimal digits, or a "0x" prefix followed by hex digits.
func isLegacyShapePart(p string) bool {
	if len(p) > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') {
		return allHexDigits(p[2:])
	}
	return allDigits(p)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allHexDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// parseLegacyIPv4 converts a classic inet_aton literal to its 32-bit address.
// It accepts "a" (the whole address), "a.b" (b fills the low 24 bits),
// "a.b.c" (c fills the low 16 bits) and "a.b.c.d". Only the final part is wide;
// every earlier part must fit in one octet.
//
// A part with a leading zero is rejected rather than resolved. "010.0.0.1"
// reads as 8.0.0.1 under inet_aton's octal rule and as 10.0.0.1 under a plain
// decimal reading, and the two readings disagree about a private range, so
// the literal is ambiguous and its caller denies it.
//
// ok is false for anything that is not a valid legacy literal; callers must
// treat that as "deny", not "it is a name".
func parseLegacyIPv4(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := legacyPart(p)
		if !ok {
			return nil, false
		}
		vals[i] = v
	}

	var addr uint32
	switch len(vals) {
	case 1:
		if vals[0] > math.MaxUint32 {
			return nil, false
		}
		addr = uint32(vals[0])
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil, false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil, false
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])
	default:
		for _, v := range vals {
			if v > 0xff {
				return nil, false
			}
		}
		addr = uint32(vals[0])<<24 | uint32(vals[1])<<16 | uint32(vals[2])<<8 | uint32(vals[3])
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)), true
}

// legacyPart parses one inet_aton component: decimal, or hex with a "0x"
// prefix. strconv.ParseUint is called with an explicit base, which makes it
// reject the "0x" prefix itself, so the prefix is stripped first.
func legacyPart(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	// A bare "0" is an ordinary zero; any other leading zero is the ambiguous
	// octal spelling described in parseLegacyIPv4.
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
