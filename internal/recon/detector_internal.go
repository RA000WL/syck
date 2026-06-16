package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var internalRE = regexp.MustCompile(`(?i)/(internal|private|intranet|corp)(\b|/|$)`)
var internalHostRE = regexp.MustCompile(`(?i)(internal\.|corp\.|\.local)`)
var privateIP10RE = regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
var privateIP172RE = regexp.MustCompile(`\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b`)
var privateIP192RE = regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`)
var localhostRE = regexp.MustCompile(`\b(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0)\b`)
var cloudMetadataRE = regexp.MustCompile(`\b169\.254\.169\.254\b`)
var k8sServiceRE = regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b`)
var dockerServiceRE = regexp.MustCompile(`(?i)(?:docker|container)[_.]?(?:host|name|id|service)\b`)
var internalPathRE = regexp.MustCompile(`(?i)/(?:debug|trace|admin|internal|private|staging|dev|test|sandbox|legacy|hidden)(?:/|$)`)
var sensitivePortRE = regexp.MustCompile(`:(?:3306|5432|6379|27017|9200|9300|11211|5984|8500|8600|8200)\b`)

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

func classifyInternal(url string) string {
	// Check for internal paths
	if internalRE.MatchString(url) || internalPathRE.MatchString(url) {
		return "internal"
	}
	// Check for internal hostnames
	if internalHostRE.MatchString(url) || k8sServiceRE.MatchString(url) {
		return "internal_host"
	}
	// Check for private IPs (potential SSRF)
	if privateIP10RE.MatchString(url) || privateIP172RE.MatchString(url) || privateIP192RE.MatchString(url) {
		return "private_ip"
	}
	// Check for localhost/loopback
	if localhostRE.MatchString(url) {
		return "localhost"
	}
	// Check for cloud metadata endpoint (high severity - SSRF target)
	if cloudMetadataRE.MatchString(url) {
		return "cloud_metadata"
	}
	// Check for Docker/K8s references
	if dockerServiceRE.MatchString(url) {
		return "container_service"
	}
	// Check for sensitive database/service ports
	if sensitivePortRE.MatchString(url) {
		return "sensitive_port"
	}
	return ""
}
