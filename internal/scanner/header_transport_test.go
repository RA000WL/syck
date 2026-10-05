package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderTransport_CloneAndInject(t *testing.T) {
	var gotHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer ts.Close()

	transport := &headerTransport{
		base: http.DefaultTransport,
		headers: map[string][]string{
			"Authorization": {"Bearer test-token"},
			"Cookie":        {"a=1", "b=2"},
			"X-Custom":      {"val1"},
		},
	}
	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Original", "yes")
	client.Do(req)

	if gotHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf("Authorization header: got %q", gotHeaders.Get("Authorization"))
	}
	cookies := gotHeaders.Values("Cookie")
	if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("Cookie headers: got %v", cookies)
	}
	if gotHeaders.Get("Original") != "yes" {
		t.Error("original header should be preserved")
	}
}

func TestHeaderTransport_CloneDoesNotMutateOriginal(t *testing.T) {
	transport := &headerTransport{
		base:    http.DefaultTransport,
		headers: map[string][]string{"X-Injected": {"yes"}},
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Original", "yes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Injected") != "yes" {
			t.Error("expected injected header on server side")
		}
		if r.Header.Get("X-Original") != "yes" {
			t.Error("expected original header preserved")
		}
	}))
	defer ts.Close()

	client := &http.Client{Transport: transport}
	req.URL, _ = req.URL.Parse(ts.URL)
	client.Do(req)

	// Verify original request was NOT mutated
	if req.Header.Get("X-Injected") != "" {
		t.Error("original request was mutated — clone failed")
	}
}

// captureTripper records the request headers it receives.
type captureTripper struct {
	got http.Header
}

func (c *captureTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.got = req.Header.Clone()
	return &http.Response{Header: make(http.Header), Request: req}, nil
}

func newCredTransport(base http.RoundTripper) *headerTransport {
	return &headerTransport{
		base: base,
		headers: map[string][]string{
			"Authorization": {"Bearer x"},
			"Cookie":        {"a=1"},
			"X-Api-Key":     {"secret-key"},
			"X-Custom":      {"keep-me"},
		},
	}
}

// withRedirectChain builds a request to target whose redirect history starts at origin.
func withRedirectChain(t *testing.T, origin, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	originReq, err := http.NewRequest("GET", origin, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Response = &http.Response{Request: originReq}
	return req
}

func TestHeaderTransportCrossOriginStrip(t *testing.T) {
	base := &captureTripper{}
	transport := newCredTransport(base)

	req := withRedirectChain(t, "http://example.com/start", "http://evil.com/next")
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatal(err)
	}

	if got := base.got.Get("Authorization"); got != "" {
		t.Errorf("cross-host Authorization should be stripped, got %q", got)
	}
	if got := base.got.Get("Cookie"); got != "" {
		t.Errorf("cross-host Cookie should be stripped, got %q", got)
	}
	if got := base.got.Get("X-Api-Key"); got != "" {
		t.Errorf("cross-host X-Api-Key should be stripped, got %q", got)
	}
	if got := base.got.Get("X-Custom"); got != "keep-me" {
		t.Errorf("cross-host X-Custom should be kept, got %q", got)
	}
}

func TestHeaderTransportSameOriginKeep(t *testing.T) {
	base := &captureTripper{}
	transport := newCredTransport(base)

	req := withRedirectChain(t, "http://example.com/start", "http://example.com:8080/next")
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatal(err)
	}

	if got := base.got.Get("Authorization"); got != "Bearer x" {
		t.Errorf("same-host Authorization should be kept, got %q", got)
	}
	if got := base.got.Get("Cookie"); got != "a=1" {
		t.Errorf("same-host Cookie should be kept, got %q", got)
	}
	if got := base.got.Get("X-Api-Key"); got != "secret-key" {
		t.Errorf("same-host X-Api-Key should be kept, got %q", got)
	}
	if got := base.got.Get("X-Custom"); got != "keep-me" {
		t.Errorf("same-host X-Custom should be kept, got %q", got)
	}
}
