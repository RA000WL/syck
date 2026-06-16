// Package crawler provides WAF bypass techniques for security scanning.
package crawler

import (
	"math/rand"
	"net/http"
	"strings"
)

// WAFBypassConfig holds configuration for WAF bypass
type WAFBypassConfig struct {
	EnableRotation bool
	MaxRetries     int
	BypassHeaders  map[string][]string
}

// DefaultWAFBypassConfig returns default WAF bypass configuration
func DefaultWAFBypassConfig() WAFBypassConfig {
	return WAFBypassConfig{
		EnableRotation: true,
		MaxRetries:     3,
		BypassHeaders:  GetBypassHeaders(),
	}
}

// GetBypassHeaders returns headers that may help bypass WAF rules
func GetBypassHeaders() map[string][]string {
	return map[string][]string{
		// IP spoofing headers (some WAFs trust these)
		"X-Forwarded-For": {
			"127.0.0.1",
			"localhost",
			"10.0.0.1",
			"192.168.1.1",
			"::1",
		},
		"X-Real-IP": {
			"127.0.0.1",
			"10.0.0.1",
		},
		"X-Client-IP": {
			"127.0.0.1",
			"10.0.0.1",
		},

		// Origin/Referer bypass
		"Origin": {
			"http://localhost",
			"http://127.0.0.1",
			"https://www.google.com",
			"https://www.facebook.com",
		},
		"Referer": {
			"http://localhost",
			"https://www.google.com/",
			"https://www.bing.com/",
		},

		// Accept headers (some WAFs check these)
		"Accept": {
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"application/json",
			"*/*",
		},
		"Accept-Language": {
			"en-US,en;q=0.9",
			"en-GB,en;q=0.9",
			"en;q=0.9",
		},
		"Accept-Encoding": {
			"gzip, deflate, br",
			"gzip, deflate",
			"identity",
		},

		// Cache bypass
		"Cache-Control": {
			"no-cache",
			"no-store, no-cache",
			"max-age=0",
		},
		"Pragma": {
			"no-cache",
		},

		// Connection headers
		"Connection": {
			"keep-alive",
			"close",
		},

		// Custom headers that some WAFs don't inspect
		"X-Requested-With": {
			"XMLHttpRequest",
		},
		"X-CSRF-Token": {
			"1",
			"dummy",
		},
	}
}

// RandomBypassHeaders returns a set of random bypass headers
func RandomBypassHeaders() map[string]string {
	headers := make(map[string]string)
	bypassHeaders := GetBypassHeaders()

	// Select 2-4 random headers
	numHeaders := 2 + rand.Intn(3)
	selected := make(map[string]bool)

	for i := 0; i < numHeaders && i < len(bypassHeaders); i++ {
		for key, values := range bypassHeaders {
			if selected[key] {
				continue
			}
			headers[key] = values[rand.Intn(len(values))]
			selected[key] = true
			break
		}
	}

	return headers
}

// ApplyBypassHeaders applies WAF bypass headers to a request
func ApplyBypassHeaders(req *http.Request, config WAFBypassConfig) {
	if !config.EnableRotation {
		return
	}

	// Apply random bypass headers
	for key, values := range config.BypassHeaders {
		if req.Header.Get(key) == "" && len(values) > 0 {
			req.Header.Set(key, values[rand.Intn(len(values))])
		}
	}
}

// RotateUserAgent changes the User-Agent to a random value
func RotateUserAgent(req *http.Request) {
	req.Header.Set("User-Agent", RandomUserAgent())
}

// ShouldBypass determines if a response indicates WAF blocking
func ShouldBypass(resp *http.Response) bool {
	// Check for common WAF block indicators
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		return true
	}

	// Check for WAF-specific headers
	wafHeaders := []string{
		"X-CDN",
		"X-Cache",
		"X-WAF-Event",
		"X-Blocked",
		"CF-Ray",
		"X-Sucuri-ID",
		"X-ModSecurity",
	}

	for _, header := range wafHeaders {
		if resp.Header.Get(header) != "" {
			return true
		}
	}

	// Check for common WAF block pages in body
	// (This is a simple check - real implementation would read body)
	return false
}

// GetWAFBypassUserAgents returns User-Agents known to bypass some WAFs
func GetWAFBypassUserAgents() []string {
	return []string{
		// Googlebot (some WAFs allow search engines)
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",

		// Older browsers (some WAFs have legacy rules)
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.0.0 Safari/537.36",

		// curl (some APIs don't block curl)
		"curl/7.68.0",
		"curl/7.81.0",

		// wget
		"Wget/1.21",
		"Wget/1.21.3",

		// Python requests
		"python-requests/2.28.0",
		"python-requests/2.31.0",

		// Go HTTP client
		"Go-http-client/1.1",
		"Go-http-client/2.0",
	}
}

// RandomWAFBypassUserAgent returns a random WAF bypass User-Agent
func RandomWAFBypassUserAgent() string {
	agents := GetWAFBypassUserAgents()
	return agents[rand.Intn(len(agents))]
}

// IsWAFBlocked checks if a response indicates WAF blocking
func IsWAFBlocked(statusCode int, headers http.Header, body string) bool {
	// Check status code
	if statusCode == 403 || statusCode == 406 || statusCode == 429 || statusCode == 503 {
		return true
	}

	// Check for WAF headers
	wafIndicators := []string{
		"X-WAF-Event",
		"X-Blocked",
		"X-ModSecurity",
		"X-Sucuri-ID",
		"CF-Ray",
		"X-CDN: Sucuri",
	}

	for _, indicator := range wafIndicators {
		parts := strings.SplitN(indicator, ": ", 2)
		if len(parts) == 2 {
			if headers.Get(parts[0]) == parts[1] {
				return true
			}
		} else if headers.Get(indicator) != "" {
			return true
		}
	}

	// Check body for common WAF block pages
	blockPages := []string{
		"Access Denied",
		"Blocked by WAF",
		"Security Violation",
		"Request Rejected",
		"403 Forbidden",
		"Web Application Firewall",
		"ModSecurity",
		"Sucuri WebSite Firewall",
	}

	bodyLower := strings.ToLower(body)
	for _, blockPage := range blockPages {
		if strings.Contains(bodyLower, strings.ToLower(blockPage)) {
			return true
		}
	}

	return false
}
