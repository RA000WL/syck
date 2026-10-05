package scanner

import (
	"net/http"
	"strings"
)

// headerTransport injects custom headers into all HTTP requests.
// It clones each request before modification to avoid mutating the original.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string][]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	crossHost := isCrossHostRedirect(req)
	for k, vals := range t.headers {
		if crossHost && isCredentialHeader(k) {
			continue
		}
		for _, v := range vals {
			cloned.Header.Add(k, v)
		}
	}
	return t.base.RoundTrip(cloned)
}

// isCredentialHeader reports whether a header carries credentials that must
// not cross host boundaries. Comparison is case-insensitive.
func isCredentialHeader(k string) bool {
	return strings.EqualFold(k, "Authorization") ||
		strings.EqualFold(k, "Cookie") ||
		strings.EqualFold(k, "X-Api-Key")
}

// isCrossHostRedirect tracks the redirect origin via req.Response chain
// (Go attaches the previous response to each redirected request) and reports
// whether the current request targets a different host than the origin.
// Hostname comparison only — port differences do not count as cross-host.
func isCrossHostRedirect(req *http.Request) bool {
	origin := req
	for origin.Response != nil && origin.Response.Request != nil {
		origin = origin.Response.Request
	}
	if origin == req {
		return false
	}
	if origin.URL == nil || req.URL == nil {
		return false
	}
	return !strings.EqualFold(origin.URL.Hostname(), req.URL.Hostname())
}
