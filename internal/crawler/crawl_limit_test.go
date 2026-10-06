package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrawlLimitNotOvershot(t *testing.T) {
	// Index links to many pages; each page links onward. Concurrency widens
	// the window in which concurrent workers enqueue while the BFS loop
	// checks the limit.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		var links strings.Builder
		for i := 0; i < 30; i++ {
			links.WriteString(fmt.Sprintf(`<a href="/p%d">p%d</a>`, i, i))
		}
		_, _ = w.Write([]byte(links.String()))
	}))
	defer ts.Close()

	cfg := CrawlConfig{Limit: 10, MaxDepth: 3, Concurrency: 10, HostConcurrency: 10}
	results := Crawl([]string{ts.URL + "/index"}, cfg)
	if len(results) > 10 {
		t.Fatalf("crawl limit overshot: got %d results, want <= 10", len(results))
	}
}

func TestJsMapRespectsScope(t *testing.T) {
	var mapFetches int32
	// /app.js links to page1..page5 (extracted from JS), and its .js suffix
	// also triggers the auto-enqueued /app.js.map. If the .map URL bypasses
	// the scope filter at enqueue time, it is still marked visited (wasting a
	// Limit slot) and displaces legitimate in-scope pages.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
		case r.URL.Path == "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/page1");fetch("/page2");fetch("/page3");fetch("/page4");fetch("/page5");`))
		case strings.HasSuffix(r.URL.Path, ".map"):
			atomic.AddInt32(&mapFetches, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":3}`))
		case strings.HasPrefix(r.URL.Path, "/page"):
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`ok`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	// Scope matches only in-app paths and excludes .map files.
	scope := regexp.MustCompile(`^` + regexp.QuoteMeta(ts.URL) + `/(|app\.js|page[0-9]+)$`)
	cfg := CrawlConfig{
		Limit:       7,
		MaxDepth:    3,
		Concurrency: 5,
		Scope:       scope,
		Endpoints:   true,
	}
	results := Crawl([]string{ts.URL + "/"}, cfg)

	for _, r := range results {
		if strings.HasSuffix(r.URL, ".map") {
			t.Errorf("crawled .js.map despite scope: %s", r.URL)
		}
	}
	if n := atomic.LoadInt32(&mapFetches); n != 0 {
		t.Errorf("server saw %d .map fetches, want 0", n)
	}
	// All five in-scope pages must be reachable within the budget; an
	// out-of-scope .map URL consuming a visited slot displaces one of them.
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.URL] = true
	}
	for i := 1; i <= 5; i++ {
		u := fmt.Sprintf("%s/page%d", ts.URL, i)
		if !seen[u] {
			t.Errorf("in-scope page %s displaced from crawl budget (results: %d)", u, len(results))
		}
	}
}
