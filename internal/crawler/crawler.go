package crawler

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

type CrawlConfig struct {
	Scope           *regexp.Regexp
	Limit           int
	MaxDepth        int
	Debug           bool
	HTTPClient      *http.Client
	Headless        bool
	RateLimit       int
	UserAgent       string // empty = random rotation, set = fixed UA
	Cookies         bool   // enable cookie jar (default true for URL mode)
	CookieFile      string // path to persist cookies between runs (empty = in-memory)
	Concurrency     int    // max concurrent fetches (default 10)
	HostConcurrency int    // max concurrent fetches per host (default 2)
	RespectRobots   bool   // respect robots.txt Disallow rules (default true)
}

type hostRateLimiter struct {
	mu       sync.Mutex
	lastTime map[string]time.Time
	minGap   time.Duration
}

func newHostRateLimiter(rps int) *hostRateLimiter {
	if rps <= 0 {
		return nil
	}
	return &hostRateLimiter{
		lastTime: make(map[string]time.Time),
		minGap:   time.Second / time.Duration(rps),
	}
}

func (h *hostRateLimiter) Wait(host string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if last, ok := h.lastTime[host]; ok {
		wait := h.minGap - time.Since(last)
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	h.lastTime[host] = time.Now()
}

type CrawledURL struct {
	URL         string
	Content     string
	ContentType string
	Depth       int
}

// crawler holds state for a crawl session.
type crawler struct {
	config     CrawlConfig
	client     *http.Client
	rateLim    *hostRateLimiter
	hostSema   *HostSemaphores
	robots     *RobotsCache
	mu         sync.Mutex // protects results and visited
	results    []CrawledURL
	visited    map[string]bool
	queue      []queueEntry
	queueMu    sync.Mutex
	debug      bool
}

type queueEntry struct {
	url   string
	depth int
}

var defaultHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// Crawl fetches URLs and discovers linked pages via BFS.
// This is the public API — creates a crawler and runs it.
func Crawl(initialURLs []string, cfg CrawlConfig) []CrawledURL {
	if cfg.Limit <= 0 {
		cfg.Limit = 100
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.HostConcurrency <= 0 {
		cfg.HostConcurrency = 2
	}

	// Build HTTP client with optional cookie jar
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		}
	}
	if cfg.Cookies {
		jar := newCookieJar(cfg.CookieFile)
		client.Jar = jar
	}

	c := &crawler{
		config:  cfg,
		client:  client,
		rateLim: newHostRateLimiter(cfg.RateLimit),
		hostSema: NewHostSemaphores(cfg.Concurrency, cfg.HostConcurrency),
		visited: make(map[string]bool),
		debug:   cfg.Debug,
	}

	// Initialize robots.txt cache if enabled
	if cfg.RespectRobots {
		c.robots = NewRobotsCache(client, cfg.UserAgent)
	}

	// Seed the queue
	for _, u := range initialURLs {
		c.queue = append(c.queue, queueEntry{url: u, depth: 0})
	}

	// Headless browser setup
	var headless *HeadlessBrowser
	if cfg.Headless {
		var err error
		headless, err = NewHeadlessBrowser()
		if err != nil {
			if c.debug {
				fmt.Printf("[debug] headless browser failed: %v, falling back to HTTP\n", err)
			}
		} else {
			defer headless.Close()
		}
	}

	// BFS loop with parallel fetching
	var wg sync.WaitGroup
	for len(c.visited) < cfg.Limit {
		entry := c.nextURL()
		if entry == nil {
			// Wait for in-flight requests to finish before checking again
			wg.Wait()
			entry = c.nextURL()
			if entry == nil {
				break // no more URLs to crawl
			}
		}

		if entry.depth > cfg.MaxDepth {
			continue
		}
		if cfg.Scope != nil && !cfg.Scope.MatchString(entry.url) {
			continue
		}

		c.markVisited(entry.url)

		// Rate limit per host
		if parsed, err := url.Parse(entry.url); err == nil && c.rateLim != nil {
			c.rateLim.Wait(parsed.Hostname())
		}

		// Acquire semaphores (blocks if at capacity)
		host := ""
		if parsed, err := url.Parse(entry.url); err == nil {
			host = parsed.Hostname()
		}
		c.hostSema.Acquire(host)

		entryVal := *entry
		wg.Add(1)
		go func(e queueEntry, h string) {
			defer wg.Done()
			defer c.hostSema.Release(h)

			// Check robots.txt
			if c.robots != nil && !c.robots.Allowed(e.url) {
				if c.debug {
					fmt.Printf("[debug] robots.txt disallows %s\n", e.url)
				}
				return
			}

			// Respect crawl-delay from robots.txt
			if c.robots != nil {
				if delay := c.robots.CrawlDelay(e.url); delay > 0 {
					time.Sleep(delay)
				}
			}

			var content, contentType string
			var fetchErr error

			// Try headless for HTML pages, fall back to HTTP
			if headless != nil {
				content, fetchErr = headless.FetchPage(e.url, 15*time.Second)
				contentType = "text/html"
				if fetchErr != nil && c.debug {
					fmt.Printf("[debug] headless fetch %s: %v, trying HTTP\n", e.url, fetchErr)
				}
			}

			if content == "" {
				content, contentType, fetchErr = fetchURL(c.client, e.url, c.config.UserAgent)
			}

			if fetchErr != nil {
				if c.debug {
					fmt.Printf("[debug] fetch %s: %v\n", e.url, fetchErr)
				}
				return
			}

			c.addResult(CrawledURL{
				URL:         e.url,
				Content:     content,
				ContentType: contentType,
				Depth:       e.depth,
			})

			// Enqueue discovered URLs
			if e.depth < cfg.MaxDepth && len(c.visited) < cfg.Limit {
				base, _ := url.Parse(e.url)
				newURLs := ExtractURLs(content, base, contentType)
				c.enqueueURLs(newURLs, e.depth+1)
			}
		}(entryVal, host)
	}

	wg.Wait()
	return c.results
}

// nextURL pops the next unvisited URL from the queue.
func (c *crawler) nextURL() *queueEntry {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	for len(c.queue) > 0 {
		entry := c.queue[0]
		c.queue = c.queue[1:]

		c.mu.Lock()
		visited := c.visited[entry.url]
		c.mu.Unlock()

		if !visited {
			return &entry
		}
	}
	return nil
}

// markVisited marks a URL as visited.
func (c *crawler) markVisited(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[url] = true
}

// addResult appends a crawled URL to results.
func (c *crawler) addResult(r CrawledURL) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.results = append(c.results, r)
}

// enqueueURLs adds new URLs to the queue if not already visited.
func (c *crawler) enqueueURLs(urls []string, depth int) {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, u := range urls {
		if !c.visited[u] {
			c.queue = append(c.queue, queueEntry{url: u, depth: depth})
		}
	}
}

func fetchURL(client *http.Client, rawURL string, customUA string) (string, string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", "", err
	}
	ua := customUA
	if ua == "" {
		ua = RandomUserAgent()
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gz.Close()
			reader = gz
		}
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return "", "", err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Auto-detect encoding and convert to UTF-8
	charset := DetectEncoding(contentType, body)
	utf8Body, _ := ConvertToUTF8(body, charset)

	return string(utf8Body), contentType, nil
}
