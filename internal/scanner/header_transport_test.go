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
