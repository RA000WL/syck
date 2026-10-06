package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchURLTruncatesAtCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		chunk := make([]byte, 64*1024)
		for i := range chunk {
			chunk[i] = 'a'
		}
		// Stream ~11MB
		for i := 0; i < 11*1024*1024/(64*1024); i++ {
			w.Write(chunk)
		}
	}))
	defer srv.Close()

	body, _, err := fetchURL(srv.Client(), srv.URL, "test-agent")
	if err != nil {
		t.Fatalf("fetchURL error: %v", err)
	}
	if len(body) > 10*1024*1024 {
		t.Fatalf("expected body <= 10MB, got %d bytes", len(body))
	}
	if len(body) == 0 {
		t.Fatal("expected non-empty body")
	}
}
