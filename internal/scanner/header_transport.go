package scanner

import "net/http"

// headerTransport injects custom headers into all HTTP requests.
// It clones each request before modification to avoid mutating the original.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string][]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	for k, vals := range t.headers {
		for _, v := range vals {
			cloned.Header.Add(k, v)
		}
	}
	return t.base.RoundTrip(cloned)
}
