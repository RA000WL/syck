package endpoints

import (
	"regexp"
	"strings"
)

type Endpoint struct {
	File     string
	Line     int
	Endpoint string
	Context  string
}

var endpointPatterns = []*regexp.Regexp{
	// API/admin/dashboard route paths (relative)
	regexp.MustCompile(`['"]((?:/api|/v\d+|/internal|/admin|/dashboard|/graphql|/rest)(?:/[a-zA-Z0-9_\-{}:]+){1,6})['"]`),
	// Auth/secret-related routes (case-insensitive, allow method prefix like "POST /login")
	regexp.MustCompile(`(?i)['"][^'"]*(/[a-z0-9_\-]+/(?:user|account|admin|auth|login|token|password|key|secret|config|setting)[a-z0-9_/\-]*)['"]`),
	// fetch/axios calls (absolute HTTP URLs)
	regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](https?://[^'"]+)['"]`),
	// URL/endpoint variable assignments (absolute HTTP URLs, min 10 chars)
	regexp.MustCompile(`(?i)(?:url|endpoint|baseURL|apiURL)\s*[:=]\s*['"](https?://[^'"]{10,})['"]`),
	// WebSocket URLs (no quote requirement)
	regexp.MustCompile(`(wss?://[a-zA-Z0-9\-._]+(?:/[a-zA-Z0-9_/\-]*)?)`),
	// GraphQL endpoints
	regexp.MustCompile(`(?i)['"]((?:https?://[^'"]+)?/graphql(?:/[a-zA-Z0-9_\-]*)?)['"]`),
}

var staticAssetExts = map[string]bool{
	".png": true, ".jpg": true, ".gif": true, ".css": true,
	".ico": true, ".woff": true, ".svg": true, ".jpeg": true,
}

// ExtractEndpoints extracts API/GraphQL/WebSocket URLs from file content.
func ExtractEndpoints(path string, content string) []Endpoint {
	var endpoints []Endpoint
	seen := make(map[string]bool)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, pat := range endpointPatterns {
			for _, m := range pat.FindAllStringSubmatchIndex(line, -1) {
				if len(m) < 4 {
					continue
				}
				start, end := m[2], m[3]
				if start < 0 || end > len(line) {
					continue
				}
				ep := line[start:end]
				ep = strings.TrimSpace(ep)
				if len(ep) < 5 {
					continue
				}
				if seen[ep] {
					continue
				}
				// Skip static assets
				lower := strings.ToLower(ep)
				skip := false
				for ext := range staticAssetExts {
					if strings.HasSuffix(lower, ext) {
						skip = true
						break
					}
				}
				if skip {
					continue
				}
				seen[ep] = true
				ctx := strings.TrimSpace(line)
				if len(ctx) > 200 {
					ctx = ctx[:200]
				}
				endpoints = append(endpoints, Endpoint{
					File:     path,
					Line:     lineNum + 1,
					Endpoint: ep,
					Context:  ctx,
				})
			}
		}
	}
	return dedupSubstrings(endpoints)
}

// dedupSubstrings removes endpoints that are substrings of longer endpoints on the same line.
func dedupSubstrings(endpoints []Endpoint) []Endpoint {
	if len(endpoints) < 2 {
		return endpoints
	}
	var result []Endpoint
	for _, ep := range endpoints {
		isSub := false
		for _, other := range endpoints {
			if other.Line == ep.Line && len(other.Endpoint) > len(ep.Endpoint) && strings.Contains(other.Endpoint, ep.Endpoint) {
				isSub = true
				break
			}
		}
		if !isSub {
			result = append(result, ep)
		}
	}
	return result
}
