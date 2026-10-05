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
	normalized := strings.ToLower(strings.TrimSuffix(host, "."))
	if normalized == metadataHost {
		return false
	}

	// Literal-IP checks only (no DNS resolution in Batch 1).
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range []*net.IPNet{private10, private172, private192, loopbackV4, linkLocalV4, linkLocalV6} {
			if n.Contains(ip) {
				return false
			}
		}
		if ip.IsLoopback() {
			// Covers 127.0.0.0/8 and ::1.
			return false
		}
		if ip.IsUnspecified() {
			// 0.0.0.0 (and ::): not routable, never a legitimate fetch target.
			return false
		}
		if ip.IsLinkLocalUnicast() {
			return false
		}
		return true
	}

	return true
}
