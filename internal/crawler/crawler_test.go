package crawler

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestCrawlSingleJS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`var key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12";`))
	}))
	defer ts.Close()

	results := Crawl([]string{ts.URL}, CrawlConfig{Limit: 10, MaxDepth: 0})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].URL != ts.URL {
		t.Errorf("URL = %q, want %q", results[0].URL, ts.URL)
	}
	if results[0].Content == "" {
		t.Error("content is empty")
	}
}

func TestCrawlScopeFilter(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script src="https://cdn.example.com/lib.js"></script>
<script src="/local.js"></script>`))
	}))
	defer ts.Close()

	scope := regexp.MustCompile(`localhost`)
	results := Crawl([]string{ts.URL}, CrawlConfig{Scope: scope, Limit: 10, MaxDepth: 1})

	for _, r := range results {
		if r.URL == "https://cdn.example.com/lib.js" {
			t.Error("should not fetch cdn.example.com when scope is localhost")
		}
	}
}

func TestCrawlLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script src="/next.js"></script>`))
	}))
	defer ts.Close()

	results := Crawl([]string{ts.URL}, CrawlConfig{Limit: 3, MaxDepth: 5})
	if len(results) > 3 {
		t.Errorf("expected <= 3 results, got %d", len(results))
	}
}
