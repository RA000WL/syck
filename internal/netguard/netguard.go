// Package netguard gates secondary fetches against SSRF to private ranges.
//
// Batch 1 performs literal-IP checks only: no DNS resolution. DNS hostnames
// are allowed; only literal IPs in private ranges and the well-known cloud
// metadata hostname are denied.
package netguard

import (
	"net"
	"net/url"
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
// without trailing dot).
// All other inputs (public IPs, DNS hostnames, unparseable-but-harmless
// relatives) return true, except unparseable absolute URLs which return false.
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

	// Literal-IP checks only (no DNS resolution in Batch 1).
	if ip := net.ParseIP(host); ip != nil {
		return !IsBlockedIP(ip)
	}

	return true
}
