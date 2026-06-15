package recon

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

// SecurityHeaderDetector analyzes HTTP security headers on discovered URLs.
type SecurityHeaderDetector struct {
	client *http.Client
}

// NewSecurityHeaderDetector creates a detector that checks security headers
// using the provided HTTP client.
func NewSecurityHeaderDetector(client *http.Client) *SecurityHeaderDetector {
	return &SecurityHeaderDetector{client: client}
}

// Detect checks security headers on unique origins for the given URLs.
func (d *SecurityHeaderDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	seen := make(map[string]bool)

	for _, u := range urls {
		origin := detectOrigin(u)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		hdr, cookies, status, err := fetchHeaders(d.client, u)
		if err != nil || status >= 500 {
			continue
		}

		isHTTPS := strings.HasPrefix(u, "https://")
		out = append(out, d.checkHeaders(origin, u, hdr, cookies, isHTTPS)...)

		// Security.txt check (HTTPS only)
		if isHTTPS {
			out = append(out, d.checkSecurityTxt(d.client, origin)...)
		}
	}

	return out
}

// detectOrigin extracts scheme://host[:port] for deduplication.
func detectOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// fetchHeaders makes a HEAD request (falling back to GET on failure) and
// returns response headers, parsed cookies, status code, and error.
func fetchHeaders(client *http.Client, rawURL string) (http.Header, []*http.Cookie, int, error) {
	// Try HEAD first
	status, hdr, cookies, err := doRequest(client, "HEAD", rawURL)
	if err == nil && status != 405 && status != 403 && status < 500 {
		return hdr, cookies, status, nil
	}

	// Fallback to GET with Range header to minimize bandwidth
	status, hdr, cookies, err = doRequest(client, "GET", rawURL)
	if err != nil {
		return nil, nil, 0, err
	}
	return hdr, cookies, status, nil
}

func doRequest(client *http.Client, method, rawURL string) (int, http.Header, []*http.Cookie, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if method == "GET" {
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	// Consume body to allow connection reuse (but limit reads)
	limitedReader := io.LimitReader(resp.Body, 1024)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gErr := gzip.NewReader(limitedReader)
		if gErr == nil {
			defer gr.Close()
			limitedReader = gr
		}
	}
	io.Copy(io.Discard, limitedReader)

	return resp.StatusCode, resp.Header, resp.Cookies(), nil
}

// checkHeaders runs all security header checks on a response.
func (d *SecurityHeaderDetector) checkHeaders(origin, url string, headers http.Header, cookies []*http.Cookie, isHTTPS bool) []SurfaceFinding {
	var out []SurfaceFinding

	// CSP
	out = append(out, analyzeCSP(headers)...)

	// HSTS (HTTPS only)
	if isHTTPS {
		out = append(out, analyzeHSTS(headers)...)
	}

	// X-Frame-Options
	out = append(out, analyzeXFO(headers)...)

	// X-Content-Type-Options
	out = append(out, analyzeXCTO(headers)...)

	// Referrer-Policy
	out = append(out, analyzeReferrerPolicy(headers)...)

	// Permissions-Policy
	out = append(out, analyzePermissionsPolicy(headers)...)

	// CORS
	out = append(out, d.analyzeCORS(headers, url)...)

	// Cookies (HTTPS only for Secure flag check)
	if isHTTPS {
		out = append(out, analyzeCookies(cookies)...)
	}

	// Server info disclosure
	out = append(out, analyzeServerInfo(headers)...)

	return out
}

var cspWeakInlineRE = regexp.MustCompile(`'unsafe-inline'`)
var cspWeakEvalRE = regexp.MustCompile(`'unsafe-eval'`)

func analyzeCSP(headers http.Header) []SurfaceFinding {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityHigh, Source: "missing-csp"}}
	}

	var out []SurfaceFinding
	if strings.Contains(csp, "default-src *") || strings.Contains(csp, "script-src *") {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-wildcard"})
	}
	if cspWeakInlineRE.MatchString(csp) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-unsafe-inline"})
	}
	if cspWeakEvalRE.MatchString(csp) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-unsafe-eval"})
	}
	return out
}

func analyzeHSTS(headers http.Header) []SurfaceFinding {
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityMedium, Source: "missing-hsts"}}
	}

	// Parse max-age
	idx := strings.Index(hsts, "max-age=")
	if idx >= 0 {
		val := hsts[idx+8:]
		if end := strings.IndexAny(val, ";, "); end >= 0 {
			val = val[:end]
		}
		if age, err := strconv.Atoi(val); err == nil && age < 31536000 {
			return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityLow, Source: "weak-hsts"}}
		}
	}
	return nil
}

func analyzeXFO(headers http.Header) []SurfaceFinding {
	if headers.Get("X-Frame-Options") != "" {
		return nil
	}
	// Check if CSP has frame-ancestors
	csp := headers.Get("Content-Security-Policy")
	if strings.Contains(csp, "frame-ancestors") {
		return nil
	}
	return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityMedium, Source: "missing-xfo"}}
}

var versionRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

func analyzeXCTO(headers http.Header) []SurfaceFinding {
	if headers.Get("X-Content-Type-Options") == "nosniff" {
		return nil
	}
	return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityLow, Source: "missing-xcto"}}
}

func analyzeReferrerPolicy(headers http.Header) []SurfaceFinding {
	if headers.Get("Referrer-Policy") == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-referrer-policy"}}
	}
	return nil
}

func analyzePermissionsPolicy(headers http.Header) []SurfaceFinding {
	if headers.Get("Permissions-Policy") == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-permissions-policy"}}
	}
	return nil
}

func (d *SecurityHeaderDetector) analyzeCORS(headers http.Header, url string) []SurfaceFinding {
	acao := headers.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}

	var out []SurfaceFinding
	acac := strings.ToLower(headers.Get("Access-Control-Allow-Credentials"))

	if acao == "*" {
		if acac == "true" {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityHigh, Source: "cors-wildcard-credentials"})
		} else {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "cors-wildcard"})
		}
		return out
	}

	// Test origin reflection
	if detectOriginReflection(d.client, url) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityHigh, Source: "cors-origin-reflection"})
	}

	return out
}

func detectOriginReflection(client *http.Client, targetURL string) bool {
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	return acao == "https://evil.example.com"
}

func analyzeCookies(cookies []*http.Cookie) []SurfaceFinding {
	var out []SurfaceFinding
	hasSecure, hasHttpOnly, hasSameSite := false, false, false
	for _, c := range cookies {
		if c.Secure {
			hasSecure = true
		}
		if c.HttpOnly {
			hasHttpOnly = true
		}
		// SameSite value 0 means unset (Go default); SameSiteDefaultMode (1) is also not meaningful
		if c.SameSite == http.SameSiteStrictMode || c.SameSite == http.SameSiteLaxMode || c.SameSite == http.SameSiteNoneMode {
			hasSameSite = true
		}
	}
	if len(cookies) > 0 && !hasSecure {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "cookie-no-secure"})
	}
	if len(cookies) > 0 && !hasHttpOnly {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "cookie-no-httponly"})
	}
	if len(cookies) > 0 && !hasSameSite {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "cookie-no-samesite"})
	}
	return out
}

func analyzeServerInfo(headers http.Header) []SurfaceFinding {
	var out []SurfaceFinding
	if server := headers.Get("Server"); server != "" {
		if versionRE.MatchString(server) {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "server-version-disclosure"})
		}
	}
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		if versionRE.MatchString(xpb) {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "x-powered-by-disclosure"})
		}
	}
	return out
}

func (d *SecurityHeaderDetector) checkSecurityTxt(client *http.Client, origin string) []SurfaceFinding {
	resp, err := client.Get(origin + "/.well-known/security.txt")
	if err != nil {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-security-txt"}}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	if resp.StatusCode != 200 {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-security-txt"}}
	}
	return nil
}
