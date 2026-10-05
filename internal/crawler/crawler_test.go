package crawler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"
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

func TestCrawlConcurrentVisitedRace(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small delay keeps worker goroutines in-flight (in enqueueURLs /
		// visitedCount / .js.map block) while the main BFS loop dequeues in
		// nextURL, widening the interleaving window for -race to observe
		// (regression test for the dual-mutex visited-map race).
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		// Every page links to the same set of URLs plus a shared .js file
		// (exercises enqueueURLs + the .js.map enqueue block concurrently).
		_, _ = w.Write([]byte(`<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>` +
			`<script src="/app.js"></script>`))
	}))
	defer ts.Close()

	// Seed with a mix of duplicate URLs to force concurrent
	// nextURL/markVisited/visitedCount/enqueueURLs interleavings.
	var seeds []string
	for i := 0; i < 10; i++ {
		seeds = append(seeds, ts.URL, ts.URL+"/a", ts.URL+"/b")
	}
	cfg := CrawlConfig{Limit: 20, MaxDepth: 1, Concurrency: 10, HostConcurrency: 2, Endpoints: true}
	results := Crawl(seeds, cfg)

	// Deduped results: no URL fetched twice.
	seen := make(map[string]bool)
	for _, r := range results {
		if seen[r.URL] {
			t.Errorf("duplicate URL in results: %s", r.URL)
		}
		seen[r.URL] = true
	}
	if len(results) == 0 {
		t.Fatal("expected at least 1 result")
	}
}

// TestVisitedMapConcurrentHammer directly hammers every accessor of the
// crawler visited map concurrently. Unlike TestCrawlConcurrentVisitedRace
// (which goes through the public Crawl API where HostConcurrency serializes
// workers), this white-box test forces nextURL vs markVisited/visitedCount/
// enqueueURLs interleavings every run, so `go test -race` flags any future
// dual-mutex regression on the visited map. Hermetic: no network.
func TestVisitedMapConcurrentHammer(t *testing.T) {
	c := &crawler{visited: make(map[string]bool)}

	const unique = 50
	urls := make([]string, unique)
	for i := range urls {
		urls[i] = fmt.Sprintf("http://example.test/p%d", i)
	}
	// Seed the queue with duplicates: each unique URL 4x.
	for r := 0; r < 4; r++ {
		for _, u := range urls {
			c.queue = append(c.queue, queueEntry{url: u, depth: 0})
		}
	}

	var retMu sync.Mutex
	returned := make(map[string]int)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				u := urls[(g+i)%len(urls)]
				if e := c.nextURL(); e != nil {
					retMu.Lock()
					returned[e.url]++
					retMu.Unlock()
				}
				c.markVisited(u)
				_ = c.visitedCount()
				c.enqueueURLs([]string{u}, 0)
			}
		}(g)
	}
	wg.Wait()

	// Drain leftovers (enqueueURLs may have appended entries before their
	// URL was marked visited); every pop is still deduped by nextURL.
	for {
		e := c.nextURL()
		if e == nil {
			break
		}
		returned[e.url]++
	}

	// No URL may be handed out twice: nextURL checks and marks visited
	// atomically under the single-mutex discipline.
	for u, n := range returned {
		if n > 1 {
			t.Errorf("nextURL returned %s %d times, want at most once", u, n)
		}
	}
	// Every unique URL was either dequeued or explicitly marked.
	if got := c.visitedCount(); got != unique {
		t.Errorf("visitedCount = %d, want %d", got, unique)
	}
}
