package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/internalurl"
)

// dockerServiceRE has no home in internal/internalurl: the
// docker|container + host|name|id|service vocabulary appears nowhere else in
// the codebase, so extracting it would create a one-caller home for a
// regex. It stays here until a second caller exists.
//
// The other six categories delegate to internalurl, which owns the RFC 1918
// CIDR list (netguard) and the internal-path/host/port vocabulary. Do not
// reintroduce a local copy: see the [Unreleased] CHANGELOG entry for why the
// IP and metadata checks are host-parsed rather than text-matched.
var dockerServiceRE = regexp.MustCompile(`(?i)(?:docker|container)[_.]?(?:host|name|id|service)\b`)

type InternalDetector struct{}

func (InternalDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		category := classifyInternal(u)
		if category != "" {
			severity := finding.SeverityLow
			// Cloud metadata is higher severity (potential SSRF)
			if category == "cloud_metadata" {
				severity = finding.SeverityHigh
			}
			// Private IPs in URLs could indicate SSRF or misconfiguration
			if category == "private_ip" {
				severity = finding.SeverityMedium
			}
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: category,
				Severity: severity,
			})
		}
	}
	return out
}

// classifyInternal returns the internal-surface category for a URL, or "" if it
// looks public.
//
// The order of the branches IS the behavior: it is a precedence chain, not a
// set of independent checks, and the first match wins. Reordering it changes
// output silently — e.g. "http://internal.corp:5432/" must report "internal",
// not "sensitive_port". TestClassifyInternalCharacterization pins the order
// with explicit two-branch rows; do not reorder without updating it.
//
// Each predicate comes from internal/internalurl. Note that the IP, loopback,
// and metadata predicates parse the URL's host rather than text-matching the
// whole string (so a private IP or 169.254.169.254 appearing in a *path* no
// longer classifies), while the path/host/port predicates stay raw-text. The
// split and the resulting behavior deltas are documented in CHANGELOG.md.
func classifyInternal(url string) string {
	// Check for internal paths
	if internalurl.IsInternalPath(url) {
		return "internal"
	}
	// Check for internal hostnames
	if internalurl.IsInternalHost(url) {
		return "internal_host"
	}
	// Check for private IPs (potential SSRF)
	if internalurl.IsPrivateHost(url) {
		return "private_ip"
	}
	// Check for localhost/loopback
	if internalurl.IsLoopback(url) {
		return "localhost"
	}
	// Check for cloud metadata endpoint (high severity - SSRF target)
	if internalurl.IsCloudMetadata(url) {
		return "cloud_metadata"
	}
	// Check for Docker/K8s references
	if dockerServiceRE.MatchString(url) {
		return "container_service"
	}
	// Check for sensitive database/service ports
	if internalurl.IsSensitivePort(url) {
		return "sensitive_port"
	}
	return ""
}
