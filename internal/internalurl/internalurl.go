// Package internalurl is the single source of truth for "is this URL
// internal?" — private network, loopback, cloud metadata, internal hostname,
// internal path, or exposed sensitive service port.
//
// It exists because that vocabulary was previously spelled out as a dozen
// ad-hoc regexes spread across internal/recon, internal/jsanalysis, and
// internal/endpoints, each with a subtly different token list. One definition
// means a fix to the list cannot be applied to two of the three.
//
// # Host-scoped vs text-scoped
//
// The predicates split into two groups, and the difference is load-bearing
// for anything that delegates to them:
//
//   - IsPrivateHost, IsLoopback, IsCloudMetadata, IsInternalHost read the
//     URL's HOST, via hostOf. They answer "is the machine this URL points at
//     internal?", so a private IP or a .svc name appearing in a path does
//     not count.
//   - IsInternalPath and IsSensitivePort read the raw string. A path token is
//     a property of the text, and a port may appear in any position the raw
//     string puts it in.
//
// Callers that need the old whole-string text-matching behavior of
// internal/recon must be aware of the difference: it is a real behavior
// change, not a refactor, and is recorded in CHANGELOG.md.
//
// # Not for every "internal" question
//
// This package classifies a URL somebody typed. It deliberately does not
// resolve DNS, so a public name that resolves to 127.0.0.1 is not detected;
// that is netguard's concern at fetch time. It also does not replace
// endpoint extraction (internal/endpoints) or config-value extraction
// (internal/jsanalysis) — those capture substrings rather than classify
// whole URLs, and merging them here would destroy their behavior.
package internalurl

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/netguard"
)

var (
	// internalHostRE is the union of internal/recon's internalHostRE and
	// k8sServiceRE. Either alone drops real matches: "api.corp.example.com"
	// matches only the first, "svc.cluster" only the second.
	internalHostRE = regexp.MustCompile(
		`(?i)(?:internal\.|corp\.|\.local|(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b)`)

	// internalPathRE is the 13-token union of internal/recon's internalRE
	// and internalPathRE. Neither list alone is sufficient: "intranet" and
	// "corp" come only from internalRE, "admin" and "debug" only from
	// internalPathRE.
	//
	// The trailing group is \b|/|$ rather than internalPathRE's stricter /|$.
	// The four internalRE tokens carry \b, so the looser form is required to
	// keep "/internal-api" and "/corp.example.com" matching. Note that it
	// also admits "/admin?x=1" and "/sandbox.json", which the original union
	// did not; that widening is deliberate and pinned in the tests.
	internalPathRE = regexp.MustCompile(
		`(?i)/(?:admin|corp|debug|dev|hidden|internal|intranet|legacy|private|sandbox|staging|test|trace)(?:\b|/|$)`)

	// sensitivePortRE keeps the \b terminator. Without it ":33060" matches
	// ":3306" and every long port in a URL becomes a finding.
	sensitivePortRE = regexp.MustCompile(
		`:(?:3306|5432|6379|27017|9200|9300|11211|5984|8500|8600|8200)\b`)

	// metadataIP is the AWS/Azure/GCP link-local metadata address. Compared
	// for equality rather than as a CIDR: the whole 169.254/16 is link-local
	// and must never be fetched, but only this one address is the metadata
	// service, and classifying all of it as metadata would invent findings.
	metadataIP = net.IPv4(169, 254, 169, 254)
)

// hostOf returns the hostname of raw, lowercased, with any port, userinfo,
// bracketing, and trailing root dot removed.
//
// It exists because url.Parse alone is not enough. url.Parse puts a bare
// "10.0.0.1" in Path rather than Host, so u.Hostname() returns "" for the
// exact input IsPrivateHost exists to catch. It also rejects "172.16.5.4:8080",
// "127.0.0.1:8080", "[::1]" and "::1" outright with a parse error, so an
// err-nil-only implementation drops every bare host:port and bare IPv6
// literal. Any of those failures would turn a security predicate into a
// silent no-op.
//
// A raw string with no host component at all (a bare path, an empty string)
// yields "".
func hostOf(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		// Hostname(), never Host: it strips the port, and netguard's
		// IsMetadataHost takes a bare hostname. Passing Host would leave
		// "metadata.google.internal:8080" unmatched and allow the GCP
		// metadata host — an SSRF bypass.
		return normalizeHost(u.Hostname())
	}

	// No scheme/authority, or a parse error: the string may itself be a bare
	// host, with or without a port or a trailing path.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+len("://"):]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") {
		// Bracketed IPv6 literal, optionally with a port. Keep the inside
		// only; net.ParseIP rejects "[::1]".
		if j := strings.IndexByte(s, ']'); j >= 0 {
			return normalizeHost(s[1:j])
		}
		return normalizeHost(s[1:])
	}
	// A bare IPv6 literal has several colons and no port; "host:port" has
	// exactly one. Only strip in the second case, or "::1" becomes ":".
	if strings.Count(s, ":") == 1 {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			s = s[:i]
		}
	}
	return normalizeHost(s)
}

// normalizeHost lowercases and drops a single trailing root dot, so that
// "localhost." and "127.0.0.1." resolve the same as their dotless forms.
// This matches netguard.IsMetadataHost's own normalization.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// IsPrivateHost reports whether raw points at a host in one of the three
// RFC 1918 ranges: 10/8, 172.16/12, 192.168/16.
//
// It is deliberately narrower than netguard.IsBlockedIP. Loopback,
// link-local, and the unspecified address are all blocked from being fetched
// but are not private hosts, and a caller classifying a URL needs them
// separated: recon reports them as different categories.
func IsPrivateHost(raw string) bool {
	ip := net.ParseIP(hostOf(raw))
	return netguard.IsPrivateIP(ip)
}

// IsLoopback reports whether raw points at loopback: 127/8, ::1, the
// unspecified address (0.0.0.0 or ::), or the literal name "localhost".
//
// Accepting the name "localhost" is a DELIBERATE divergence from
// netguard.IsBlockedIP, which rejects it because Batch 1 performs no DNS
// resolution and so treats the name as an ordinary hostname. The two answer
// different questions. IsBlockedIP gates an outbound fetch, where an
// unresolvable guess is a risk; IsLoopback classifies a URL a human typed,
// where the name itself is the signal. Do not "unify" them — routing IsLoopback
// through IsBlockedIP would silently drop every localhost URL from recon.
func IsLoopback(raw string) bool {
	host := hostOf(raw)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// IsLoopback covers 127/8 and ::1; IsUnspecified covers 0.0.0.0 and ::.
	return ip.IsLoopback() || ip.IsUnspecified()
}

// IsCloudMetadata reports whether raw points at a cloud instance-metadata
// service: the 169.254.169.254 address used by AWS, Azure, GCP and DigitalOcean,
// or the GCP metadata.google.internal hostname (with or without a trailing
// dot, in any case).
func IsCloudMetadata(raw string) bool {
	host := hostOf(raw)
	if netguard.IsMetadataHost(host) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.Equal(metadataIP)
}

// IsInternalHost reports whether raw points at a host with an internal
// look: an "internal." or "corp." label, a ".local" suffix, or a
// Kubernetes-style short name ending in svc, cluster, local, or internal.
func IsInternalHost(raw string) bool {
	host := hostOf(raw)
	if host == "" {
		return false
	}
	return internalHostRE.MatchString(host)
}

// IsInternalPath reports whether raw contains an internal-looking path
// segment: admin, corp, debug, dev, hidden, internal, intranet, legacy,
// private, sandbox, staging, test, or trace.
//
// This matches the raw string rather than the parsed path, because a caller
// holding a URL cares that the token appears in it — "/internal" is a signal
// whether it is the host, the path, or a query value.
func IsInternalPath(raw string) bool {
	return internalPathRE.MatchString(raw)
}

// IsSensitivePort reports whether raw exposes a database or infrastructure
// service port: MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017,
// Elasticsearch 9200/9300, Memcached 11211, CouchDB 5984, Consul 8500/8600,
// or Vault 8200.
func IsSensitivePort(raw string) bool {
	return sensitivePortRE.MatchString(raw)
}
