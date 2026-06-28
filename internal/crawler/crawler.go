package crawler

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type CrawlConfig struct {
	Scope           *regexp.Regexp
	Limit           int
	MaxDepth        int
	Debug           bool
	Endpoints       bool
	HTTPClient      *http.Client
	Headless        bool
	RateLimit       int
	UserAgent       string
	Cookies         bool
	CookieFile      string
	Concurrency     int
	HostConcurrency int
	RespectRobots   bool
	SameDomainOnly  bool
	SitemapEnabled  bool
	URLCache        *URLCache
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
	config         CrawlConfig
	client         *http.Client
	rateLim        *hostRateLimiter
	hostSema       *HostSemaphores
	robots         *RobotsCache
	sitemapFetcher *SitemapFetcher
	mu             sync.Mutex // protects results and visited
	results        []CrawledURL
	visited        map[string]bool
	sitemapDomains map[string]bool // domains that have had sitemaps fetched
	queue          []queueEntry
	queueMu        sync.Mutex
	debug          bool
	initialHost    string
}

type queueEntry struct {
	url   string
	depth int
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
		config:         cfg,
		client:         client,
		rateLim:        newHostRateLimiter(cfg.RateLimit),
		hostSema:       NewHostSemaphores(cfg.Concurrency, cfg.HostConcurrency),
		visited:        make(map[string]bool),
		sitemapDomains: make(map[string]bool),
		debug:          cfg.Debug,
	}

	// Initialize robots.txt cache if enabled
	if cfg.RespectRobots {
		c.robots = NewRobotsCache(client, cfg.UserAgent)
	}

	// Initialize sitemap fetcher if enabled
	if cfg.SitemapEnabled {
		c.sitemapFetcher = NewSitemapFetcher(client, cfg.UserAgent)
	}

	// Seed the queue
	for _, u := range initialURLs {
		c.queue = append(c.queue, queueEntry{url: u, depth: 0})
		if c.initialHost == "" {
			if parsed, err := url.Parse(u); err == nil {
				c.initialHost = parsed.Hostname()
			}
		}
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
	for c.visitedCount() < cfg.Limit {
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
		if cfg.SameDomainOnly && c.initialHost != "" {
			if parsed, err := url.Parse(entry.url); err != nil || parsed.Hostname() != c.initialHost {
				continue
			}
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

			// Sitemap discovery: process once per domain
			if c.sitemapFetcher != nil {
				parsed, err := url.Parse(e.url)
				if err == nil {
					domain := parsed.Hostname()
					c.mu.Lock()
					alreadyProcessed := c.sitemapDomains[domain]
					c.mu.Unlock()
					if !alreadyProcessed {
						c.mu.Lock()
						c.sitemapDomains[domain] = true
						c.mu.Unlock()

						// Get sitemaps from robots.txt if available
						var robotsSitemaps []string
						if c.robots != nil {
							robotsSitemaps = c.robots.Sitemaps(e.url)
						}

						sitemapURLs := c.sitemapFetcher.FetchSitemaps(domain, robotsSitemaps)
						if c.debug {
							fmt.Printf("[debug] sitemap discovery for %s: found %d URLs\n", domain, len(sitemapURLs))
						}

						// Enqueue discovered URLs with scope filtering
						for _, sURL := range sitemapURLs {
							if cfg.Scope != nil && !cfg.Scope.MatchString(sURL) {
								continue
							}
							if cfg.SameDomainOnly && c.initialHost != "" {
								if parsed, err := url.Parse(sURL); err != nil || parsed.Hostname() != c.initialHost {
									continue
								}
							}
							c.enqueueURLs([]string{sURL}, 0)
						}
					}
				}
			}

			// Check URL cache — skip fetch if previously seen with same content
			if c.config.URLCache != nil && c.config.URLCache.IsSeen(e.url) {
				if c.debug {
					fmt.Printf("[debug] cache hit: %s\n", e.url)
				}
				return
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

			// Record in URL cache
			if c.config.URLCache != nil {
				c.config.URLCache.Record(e.url, 200, content)
			}

			c.addResult(CrawledURL{
				URL:         e.url,
				Content:     content,
				ContentType: contentType,
				Depth:       e.depth,
			})

			// V1.1: harvest source maps for JS files
			if c.config.Endpoints && strings.HasSuffix(e.url, ".js") && c.visitedCount() < cfg.Limit {
				mapURL := e.url + ".map"
				c.mu.Lock()
				alreadyQueued := c.visited[mapURL]
				c.mu.Unlock()
				if !alreadyQueued {
					c.queueMu.Lock()
					c.queue = append(c.queue, queueEntry{url: mapURL, depth: e.depth + 1})
					c.queueMu.Unlock()
				}
			}

			// Enqueue discovered URLs
			if e.depth < cfg.MaxDepth && c.visitedCount() < cfg.Limit {
				base, _ := url.Parse(e.url)
				newURLs := ExtractURLs(content, base, contentType)
				c.enqueueURLs(newURLs, e.depth+1)
			}
		}(entryVal, host)
	}

	wg.Wait()
	return c.results
}

// nextURL pops the next unvisited URL from the queue and marks it visited.
// This eliminates the race between nextURL() and markVisited() where the
// same URL could be dequeued twice by concurrent goroutines.
func (c *crawler) nextURL() *queueEntry {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	for len(c.queue) > 0 {
		entry := c.queue[0]
		c.queue = c.queue[1:]

		if c.visited[entry.url] {
			continue
		}
		c.visited[entry.url] = true
		return &entry
	}
	return nil
}

// visitedCount returns the number of visited URLs (thread-safe).
func (c *crawler) visitedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.visited)
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
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Use pooled buffer for reading
	bufPtr := BodyPool.Get().(*[]byte)
	defer BodyPool.Put(bufPtr)
	buf := (*bufPtr)[:0]

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err == nil {
			defer gz.Close()
			reader = gz
		} else {
			return "", "", fmt.Errorf("gzip decode: %w", err)
		}
	}

	// Read with growing buffer
	for {
		if len(buf) == cap(buf) {
			// Grow buffer
			newBuf := make([]byte, len(buf), cap(buf)*2)
			copy(newBuf, buf)
			buf = newBuf
		}
		n, err := reader.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil {
			break
		}
		if len(buf) > 10*1024*1024 { // 10MB limit
			break
		}
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Auto-detect encoding and convert to UTF-8
	charset := DetectEncoding(contentType, buf)
	utf8Body, _ := ConvertToUTF8(buf, charset)

	return string(utf8Body), contentType, nil
}
