package recon

import (
	"net/http"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

// WAFSignature represents a WAF detection pattern.
type WAFSignature struct {
	Name     string
	Header   string // header name to check
	Patterns []string // substrings to match in header value
	Category string
	Severity finding.Severity
}

var wafSignatures = []WAFSignature{
	// Cloudflare
	{Name: "cloudflare", Header: "server", Patterns: []string{"cloudflare"}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "cloudflare", Header: "cf-ray", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "cloudflare", Header: "cf-cache-status", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},

	// Akamai
	{Name: "akamai", Header: "x-akamai-transformed", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "akamai", Header: "akamai-origin-hop", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "akamai", Header: "server", Patterns: []string{"akamaighost"}, Category: "waf", Severity: finding.SeverityLow},

	// AWS WAF / CloudFront
	{Name: "aws_cloudfront", Header: "x-amz-cf-id", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "aws_cloudfront", Header: "x-amz-cf-pop", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "aws_waf", Header: "x-amzn-requestid", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},

	// Imperva / Incapsula
	{Name: "imperva", Header: "x-iinfo", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "imperva", Header: "x-cdn", Patterns: []string{"imperva"}, Category: "waf", Severity: finding.SeverityLow},

	// Sucuri
	{Name: "sucuri", Header: "x-sucuri-id", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "sucuri", Header: "server", Patterns: []string{"sucuri"}, Category: "waf", Severity: finding.SeverityLow},

	// F5 BIG-IP
	{Name: "bigip", Header: "server", Patterns: []string{"BIG-IP"}, Category: "waf", Severity: finding.SeverityLow},

	// Fortinet
	{Name: "fortinet", Header: "server", Patterns: []string{"fortiweb"}, Category: "waf", Severity: finding.SeverityLow},

	// ModSecurity
	{Name: "modsecurity", Header: "server", Patterns: []string{"mod_security", "modsecurity"}, Category: "waf", Severity: finding.SeverityLow},

	// Barracuda
	{Name: "barracuda", Header: "server", Patterns: []string{"barracuda"}, Category: "waf", Severity: finding.SeverityLow},

	// Datadome
	{Name: "datadome", Header: "x-datadome", Patterns: []string{""}, Category: "waf", Severity: finding.SeverityLow},

	// Fastly
	{Name: "fastly", Header: "x-served-by", Patterns: []string{"fastly"}, Category: "waf", Severity: finding.SeverityLow},
	{Name: "fastly", Header: "x-cache", Patterns: []string{"fastly"}, Category: "waf", Severity: finding.SeverityLow},
}

// WAFDetector identifies WAF/CDN/proxy signatures from HTTP response headers.
type WAFDetector struct {
	client *http.Client
}

// NewWAFDetector creates a WAF detection detector.
func NewWAFDetector(client *http.Client) *WAFDetector {
	return &WAFDetector{client: client}
}

// Detect checks URLs for WAF signatures in response headers.
func (d *WAFDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	seen := make(map[string]bool)

	for _, rawURL := range urls {
		origin := detectOrigin(rawURL)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		// Quick HEAD request to get headers
		req, err := http.NewRequest("HEAD", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Syck/1.0)")

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check each WAF signature
		for _, sig := range wafSignatures {
			val := resp.Header.Get(sig.Header)
			if val == "" {
				// For some signatures, presence of the header alone is enough
				if len(sig.Patterns) == 1 && sig.Patterns[0] == "" {
				if resp.Header.Get(sig.Header) != "" {
					out = append(out, SurfaceFinding{
						URL:      rawURL,
						Category: sig.Category,
						Severity: sig.Severity,
						Source:   "waf_" + sig.Name,
					})
					}
				}
				continue
			}

			// Check pattern match
			valLower := strings.ToLower(val)
			for _, p := range sig.Patterns {
				if p == "" || strings.Contains(valLower, strings.ToLower(p)) {
					out = append(out, SurfaceFinding{
						URL:      rawURL,
						Category: sig.Category,
						Severity: sig.Severity,
						Source:   "waf_" + sig.Name,
					})
					break
				}
			}
		}
	}

	return out
}
