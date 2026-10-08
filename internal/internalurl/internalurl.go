// Package internalurl answers "is this URL internal?" — private network,
// loopback, cloud metadata, internal hostname, internal path, or exposed
// sensitive service port. It is the single home for the ADDRESS half of that
// vocabulary (the RFC 1918 ranges, the loopback set, the metadata address) and
// for the service-port list, and it delegates the CIDR and metadata-hostname
// authority to internal/netguard rather than keeping a second copy.
//
// Those five lists were each spelled out as ad-hoc regexes inside
// internal/recon alongside the predicates extracted from internal/netguard, so
// one address could be classified one way by classifyInternal and another by
// AllowFetch. Each has exactly one definition now.
//
// Since Batch 6 Task 5 this package delegates the host→address RESOLUTION to
// netguard.ParseHostIP as well, not just the CIDR lists. It previously called
// net.ParseIP itself, which meant the two packages could still disagree about a
// host: net.ParseIP rejects the legacy inet_aton spellings and zone-scoped
// IPv6, so "http://2130706433/" was denied by AllowFetch and classified as a
// public host here. Sharing the resolver is what makes the two answers one.
//
// This is NOT a single source for the whole vocabulary, and this doc should not
// be read as claiming it is. The *path and host token* half — admin, debug,
// trace, staging, dev, test, private, hidden, legacy — is still spelled out
// five times over:
//
//	internal/recon/detector_admin.go    adminRE
//	internal/recon/detector_debug.go    debugRE
//	internal/recon/detector_staging.go  stagingRE, stagingHostRE
//	internal/endpoints/extract.go:95    internal/hidden path pattern
//	internal/endpoints/risk.go:24       internal/debug/private risk pattern
//
// Deliberately not merged here. They are separate categories with separate
// severities and different trailing rules, three of them are sibling detectors
// this batch was forbidden to touch, and collapsing them would change recon's
// output rather than de-duplicate it.
//
// The other two packages named in the original audit are deliberate non-callers.
// internal/jsanalysis extracts config *values* from JS source rather than
// classifying whole URLs, and its localhostRE is unanchored (see its comment and
// ARCHITECTURE.md section 15). internal/endpoints extracts endpoint substrings
// from ~30 patterns, one of which happens to contain internal-path vocabulary.
// Neither has a whole URL to classify, so neither can delegate without
// changing what it emits. Consequently this package has ONE production caller,
// internal/recon's classifyInternal.
//
// # Parsed vs raw-text: which predicate is which, and why
//
// The six predicates split into two groups. The rule that separates them:
// reuse netguard where netguard can help, preserve the original regex
// semantics where it cannot.
//
// PARSED (reads the URL's host, via hostOf) — these need netguard's CIDR and
// hostname authority, and parsing is what buys that reuse:
//
//	IsPrivateHost    RFC 1918 host, via netguard.IsPrivateIP
//	IsLoopback       127/8, ::1, unspecified, and the literal name "localhost"
//	IsCloudMetadata  169.254.169.254 and metadata.google.internal
//
// RAW-TEXT (matches the whole string) — these are pure vocabulary with no
// CIDR dependency, so host-parsing would buy no reuse while changing results:
//
//	IsInternalHost   internal./corp./.local and *.svc / *.cluster labels
//	IsInternalPath   admin, debug, staging, … path segments
//	IsSensitivePort  :3306, :6379, :27017, … with a \b terminator
//
// Callers depending on the parsed group's semantics must know that this is a
// real behavior change for a narrow set of inputs, recorded in CHANGELOG.md;
// the raw-text group reproduces its predecessor's regexes exactly.
//
// # Not for every "internal" question
//
// This package classifies a URL somebody typed. It deliberately does not
// resolve DNS, and nothing downstream resolves it either for classification
// purposes: netguard's AllowFetch performs literal-IP checks only, so a name
// that resolves to 127.0.0.1 — "127.0.0.1.nip.io" is the canonical case —
// is classified as an ordinary public host by both this package and
// AllowFetch. That signal is currently dropped with NO compensating control.
// Closing it needs a gate that resolves the name and checks the answer, which
// is precisely the resolution Batch 1 deliberately excluded; do not assume
// netguard covers this. It also does not replace endpoint extraction
// (internal/endpoints) or config-value extraction (internal/jsanalysis) —
// those capture substrings rather than classify whole URLs, and merging them
// here would destroy their behavior.
package internalurl

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/netguard"
)

var (
	// internalHostRE is the union of the two host-label regexes internal/recon
	// used before Batch 4c Task 4 (its internalHostRE and k8sServiceRE, both
	// since deleted in favour of this predicate). Either alone drops real
	// matches: "api.corp.example.com" matches only the first, "svc.cluster"
	// only the second.
	//
	// Matches raw text, not the parsed host: this is pure vocabulary needing
	// no netguard CIDR knowledge, so host-parsing it would buy no reuse and
	// would cost behavior. See the note on IsInternalHost.
	internalHostRE = regexp.MustCompile(
		`(?i)(?:internal\.|corp\.|\.local|(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b)`)

	// internalPathRE is the exact per-token union of internal/recon's
	// internalRE and internalPathRE: 13 tokens, but NOT 13 tokens sharing one
	// trailing rule.
	//
	// The four internalRE tokens (internal, private, intranet, corp) used
	// (?:\b|/|$). The nine internalPathRE-only tokens (debug, trace, admin,
	// staging, dev, test, sandbox, legacy, hidden) used the stricter (?:/|$).
	// The two rules stay separate here, because collapsing them onto the
	// looser one is an over-match — a single 13-token list with \b|/|$ also
	// matches "/admin?x=1" and "/sandbox.json", which the original union does
	// not. Applying (?:/|$) to all 13 errs the other way, dropping
	// "/internal-api" and "/corp.example.com", which internalRE does match.
	//
	// Verified against the original union over 400,000 generated inputs:
	// 0 mismatches in either direction.
	internalPathRE = regexp.MustCompile(
		`(?i)/(?:(?:internal|private|intranet|corp)(?:\b|/|$)|(?:debug|trace|admin|staging|dev|test|sandbox|legacy|hidden)(?:/|$))`)

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
// A leading scheme is stripped, but only a real one: a "://" appearing after
// the path, query, or fragment has already begun belongs to that component and
// is not a scheme.
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
	//
	// A "://" is a scheme only if nothing has opened the path, query, or
	// fragment first. Stripping at the first "://" ANYWHERE lets a query that
	// carries an absolute URL take over the host: for
	// "localhost?u=http://169.254.169.254/" the old code returned
	// "169.254.169.254", so recon reported that URL as a High-severity cloud
	// metadata surface instead of the Low localhost one. Requiring the scheme
	// to precede the first /, ? or # keeps the authority the user typed.
	if i := strings.Index(s, "://"); i >= 0 {
		if j := strings.IndexAny(s, "/?#"); j < 0 || j > i {
			s = s[i+len("://"):]
		}
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
// PARSED. This is the predicate that motivates hostOf existing: reusing
// netguard's CIDR list requires an actual host, and the old text-matching
// regex would classify "http://foo.com/10.0.0.1/x" as private_ip — a private
// IP in a path is not a private host. That narrowing is deliberate and is
// CHANGELOG'd in Task 4.
//
// The host is resolved with netguard.ParseHostIP, NOT net.ParseIP, so that a
// private address written in a legacy inet_aton spelling ("http://10.1/",
// "http://3232235777/") is recognized as the private address it denotes. Before
// Batch 6 Task 5 this called net.ParseIP and classified every such URL as
// public, while netguard.AllowFetch denied the same URL — one host, two
// answers, from two packages that exist to share one vocabulary.
//
// It is deliberately narrower than netguard.IsBlockedIP. Loopback,
// link-local, and the unspecified address are all blocked from being fetched
// but are not private hosts, and a caller classifying a URL needs them
// separated: recon reports them as different categories.
func IsPrivateHost(raw string) bool {
	ip, _ := netguard.ParseHostIP(hostOf(raw))
	return netguard.IsPrivateIP(ip)
}

// IsLoopback reports whether raw points at loopback: 127/8, ::1, the
// unspecified address (0.0.0.0 or ::), or the literal name "localhost".
//
// PARSED, for the same reason as IsPrivateHost: a loopback address in a path
// is not a loopback host. Parsing also lets this accept the DNS name
// "localhost" without a resolver, which the text-matching predecessor could
// only do crudely — it matched "127.0.0.X" but not "127.1.2.3" or "::1", so
// this predicate fixes those two under-matches (CHANGELOG'd in Task 4).
//
// The host is resolved with netguard.ParseHostIP, so every spelling of 127/8
// classifies alike: "http://2130706433/" and "http://127.1/" are loopback, and
// a zoned "http://[::1%25lo]/" is loopback too. See IsPrivateHost for why the
// resolver is shared rather than reimplemented.
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
	ip, ok := netguard.ParseHostIP(host)
	if !ok {
		return false
	}
	// IsLoopback covers 127/8 and ::1; IsUnspecified covers 0.0.0.0 and ::.
	return ip.IsLoopback() || ip.IsUnspecified()
}

// IsCloudMetadata reports whether raw points at a cloud instance-metadata
// service: the 169.254.169.254 address used by AWS, Azure, GCP and DigitalOcean,
// or the GCP metadata.google.internal hostname (with or without a trailing
// dot, in any case).
//
// PARSED, and must stay that way. Both halves are exact host comparisons: the
// hostname goes through netguard.IsMetadataHost, which pins suffix and prefix
// attacks ("metadata.google.internal.evil.com", "xmetadata.google.internal")
// to false, and the address is compared with net.IP.Equal rather than as a
// CIDR. Substituting a raw-text substring match for either would accept those
// attacker-controlled hostnames as the metadata service — the SSRF bypass
// netguard exists to prevent. The parsed reading costs nothing here, because
// the input class this would have fixed does not exist: recon's cloud_metadata
// branch is preceded by internal_host, so a URL carrying the GCP metadata
// HOSTNAME — "http://foo.com/metadata.google.internal/", and equally
// "http://metadata.google.internal/" — is reported as internal_host and never
// reaches this predicate. That is why the hostname half is free to stay parsed
// even though it is the half the old text regex could never match.
//
// The address half is resolved with netguard.ParseHostIP, so the legacy
// inet_aton spellings of 169.254.169.254 — "http://2852039166/" and
// "http://0xa9fea9fe/" — classify as cloud_metadata too. That is worth naming
// because it is the one input class that becomes a HIGHER-severity finding
// (High) rather than a lower one: recon reports metadata at High severity, so
// an obfuscated metadata address was previously silent and now is not.
func IsCloudMetadata(raw string) bool {
	host := hostOf(raw)
	if netguard.IsMetadataHost(host) {
		return true
	}
	ip, ok := netguard.ParseHostIP(host)
	return ok && ip.Equal(metadataIP)
}

// IsInternalHost reports whether raw contains an internal-looking host
// vocabulary: an "internal." or "corp." label, a ".local" suffix, or a
// Kubernetes-style short name ending in svc, cluster, local, or internal.
//
// RAW-TEXT, not parsed. This is pure vocabulary: it needs no CIDR knowledge,
// so host-parsing it would buy no reuse of netguard while changing behavior.
// Matching the text also preserves recon's existing results — under the
// parsed reading, "http://example.com/x.internal/y" would stop matching,
// which is drift with no compensating benefit. hostOf is deliberately not
// called here.
func IsInternalHost(raw string) bool {
	return internalHostRE.MatchString(raw)
}

// IsInternalPath reports whether raw contains an internal-looking path
// segment: admin, corp, debug, dev, hidden, internal, intranet, legacy,
// private, sandbox, staging, test, or trace.
//
// RAW-TEXT, for the same reason as IsInternalHost: pure vocabulary, no netguard
// reuse available, so parsing would only introduce drift. A token is a
// property of the text — "/internal" is a signal whether it is the host, the
// path, or a query value.
func IsInternalPath(raw string) bool {
	return internalPathRE.MatchString(raw)
}

// IsSensitivePort reports whether raw exposes a database or infrastructure
// service port: MySQL 3306, PostgreSQL 5432, Redis 6379, MongoDB 27017,
// Elasticsearch 9200/9300, Memcached 11211, CouchDB 5984, Consul 8500/8600,
// or Vault 8200.
//
// RAW-TEXT: a port appears in the authority, but matching the text preserves
// recon's behavior exactly and costs nothing, since no CIDR knowledge is
// involved. The brief's required-true cases include a bare ":5432" with no
// host to parse.
func IsSensitivePort(raw string) bool {
	return sensitivePortRE.MatchString(raw)
}
