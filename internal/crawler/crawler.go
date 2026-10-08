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
	"sync/atomic"
	"time"

	"github.com/RA000WL/syck/internal/netguard"
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
	AllowPrivateIPs bool
	URLCache        *URLCache
}

// defaultConcurrency is the fixed fetch concurrency used when the caller does
// not configure one.
//
// The crawler's workers spend nearly all their time waiting on remote servers
// (BFS over HTTP fetches), so the pool is **network-bound**, not CPU-bound.
// This is deliberately NOT scanner.EffectiveWorkers, whose fallback is
// max(runtime.NumCPU(), 2): that helper sizes a CPU-bound pool, and reusing it
// here would make the crawler's default vary with the host's core count — a
// behavior change, and probably a worse default besides. Importing
// internal/scanner to reach that helper would also be worse coupling than a
// named constant is.
const defaultConcurrency = 10

// defaultHostConcurrency is the per-host fetch cap used when the caller does
// not configure one. It is a deliberately *smaller and different* number from
// defaultConcurrency: that one sizes the total worker pool, this one bounds how
// many of those workers may hit a single host at once so a crawl stays polite
// to the site it is crawling. The two are separate knobs with separate reasons
// and must not be unified into one value.
const defaultHostConcurrency = 2

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

// Wait blocks until the per-host rate limit permits another request.
//
// h.mu guards the lastTime map only; it is never held across the sleep.
// Under concurrent callers, holding it across time.Sleep made every host
// queue behind whichever host happened to be sleeping, capping the limiter
// at N requests/sec overall rather than N per host. The crawler currently
// has a single Wait call site (the BFS dequeue loop), so that is a latent
// property of this type rather than observed crawl behavior — but it is why
// the sleep must stay outside the lock.
//
// Same-host semantics are preserved: each caller reads its own host's
// timestamp under the lock, sleeps out its own remaining gap, then re-takes
// the lock to publish its completion time. Two callers racing on the same
// host between the unlock and the re-lock may both sleep the same gap and
// wake together. That is a bounded burst: its size is bounded by the number
// of concurrent same-host callers (not by minGap), while the steady-state
// per-host rate stays bounded by minGap because the next wait for that host
// measures from the freshly published timestamp.
func (h *hostRateLimiter) Wait(host string) {
	if h == nil {
		return
	}

	wait := func() time.Duration {
		h.mu.Lock()
		defer h.mu.Unlock()
		if last, ok := h.lastTime[host]; ok {
			return h.minGap - time.Since(last)
		}
		return 0
	}()
	if wait > 0 {
		time.Sleep(wait)
	}

	func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.lastTime[host] = time.Now()
	}()
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
	mu             sync.Mutex // protects results, visited, and sitemapDomains; all visited access holds mu.
	results        []CrawledURL
	visited        map[string]bool
	sitemapDomains map[string]bool // domains that have had sitemaps fetched
	queue          []queueEntry
	// budget is the remaining number of URLs the crawl may claim. It is
	// decremented atomically (CompareAndSwap) at the single claim point so
	// concurrent workers cannot overshoot cfg.Limit.
	budget atomic.Int64
	// queueMu protects queue. Lock order wherever both are needed is
	// queueMu -> mu; never acquire queueMu while holding mu.
	queueMu     sync.Mutex
	debug       bool
	initialHost string
}

// claimBudget atomically decrements the budget and reports whether a slot
// was available. This is the one place budget is consumed, keeping the
// total number of claimed URLs <= the initial budget (cfg.Limit).
func (c *crawler) claimBudget() bool {
	for {
		b := c.budget.Load()
		if b <= 0 {
			return false
		}
		if c.budget.CompareAndSwap(b, b-1) {
			return true
		}
	}
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
		cfg.Concurrency = defaultConcurrency
	}
	if cfg.HostConcurrency <= 0 {
		cfg.HostConcurrency = defaultHostConcurrency
	}

	// Build HTTP client with optional cookie jar
	client := cfg.HTTPClient
	if client == nil {
		allowPrivate := cfg.AllowPrivateIPs
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if !allowPrivate && req.URL != nil && !netguard.AllowFetch(req.URL.String()) {
					return fmt.Errorf("blocked redirect to private IP: %s", req.URL.String())
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
	c.budget.Store(int64(cfg.Limit))

	// Initialize robots.txt cache if enabled
	if cfg.RespectRobots {
		c.robots = NewRobotsCache(client, cfg.UserAgent)
	}

	// Initialize sitemap fetcher if enabled
	if cfg.SitemapEnabled {
		c.sitemapFetcher = NewSitemapFetcher(client, cfg.UserAgent)
		c.sitemapFetcher.AllowPrivateIPs = cfg.AllowPrivateIPs
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
	for c.budget.Load() > 0 {
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

		if !c.claimBudget() {
			break
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
			if c.config.Endpoints && strings.HasSuffix(e.url, ".js") && c.budget.Load() > 0 {
				mapURL := e.url + ".map"
				// Apply the same scope/same-domain filters as normal links
				// before enqueueing, so out-of-scope maps never consume a
				// visited slot.
				inScope := true
				if cfg.Scope != nil && !cfg.Scope.MatchString(mapURL) {
					inScope = false
				}
				if cfg.SameDomainOnly && c.initialHost != "" {
					if parsed, err := url.Parse(mapURL); err != nil || parsed.Hostname() != c.initialHost {
						inScope = false
					}
				}
				if inScope {
					// Single-mutex discipline: check visited (under mu) and enqueue
					// atomically. Lock order queueMu -> mu.
					c.queueMu.Lock()
					c.mu.Lock()
					if !c.visited[mapURL] {
						c.queue = append(c.queue, queueEntry{url: mapURL, depth: e.depth + 1})
					}
					c.mu.Unlock()
					c.queueMu.Unlock()
				}
			}

			// Enqueue discovered URLs
			if e.depth < cfg.MaxDepth && c.budget.Load() > 0 {
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
// All visited access holds mu; lock order here is queueMu -> mu.
func (c *crawler) nextURL() *queueEntry {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()

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
// All visited access holds mu; lock order here is queueMu -> mu.
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

// fetchBufPool recycles fetchURL's read buffer. Without it every crawled URL
// allocates a fresh grow-by-doubling slice up to the 10MB cap — 8KB of
// intermediate slices for an ordinary page — plus a second copy for the UTF-8
// conversion and a third for the string. The pool stores *[]byte because the
// buffer is grown in place and the new header has to travel with it.
var fetchBufPool = sync.Pool{
	New: func() any {
		// Big enough for an ordinary page so the steady state never grows, but
		// small enough that a buffer lost to a P migration is cheap to replace.
		// Grown buffers are pooled too, so a crawl of big pages converges on a
		// larger buffer after the first grow.
		b := make([]byte, 0, 8*1024)
		return &b
	},
}

// maxBodyBytes is the hard cap on a fetched body: it bounds the read so a
// remote server cannot make syck allocate without limit.
const maxBodyBytes = 10 * 1024 * 1024

// maxPooledFetchBufBytes caps what goes back into fetchBufPool. Anything that
// outgrew it is dropped on the floor: one 10MB entry would pin the pool for the
// rest of the crawl and every later fetch would carry it in RSS.
const maxPooledFetchBufBytes = 1 * 1024 * 1024

// getFetchBuf borrows an empty buffer from fetchBufPool.
func getFetchBuf() *[]byte {
	return fetchBufPool.Get().(*[]byte)
}

// putFetchBuf hands the buffer back, unless it grew past maxPooledFetchBufBytes.
// The caller must be done with the bytes it holds — see fetchURL, where the Put
// deliberately follows the string copy.
func putFetchBuf(bufp *[]byte) {
	if cap(*bufp) > maxPooledFetchBufBytes {
		return
	}
	fetchBufPool.Put(bufp)
}

// readAllInto reads everything r has into *bufp, growing the buffer in place by
// doubling, exactly as io.ReadAll does — the difference is that it grows the
// caller's pooled buffer instead of allocating a fresh one per call.
//
// It stops after limit+1 bytes so the caller can detect a body that exceeded
// the cap the same way io.ReadAll(io.LimitReader(r, limit+1)) did. *bufp is
// updated to the buffer actually read into, so the caller can return that one
// to the pool.
func readAllInto(bufp *[]byte, r io.Reader, limit int) error {
	buf := (*bufp)[:0]
	for len(buf) <= limit {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		// A Read returns everything it is offered, so offering the whole spare
		// capacity would let a single call blow past limit+1 by up to another
		// full buffer. Bound the slice instead: the read stops at limit+1 bytes,
		// which is what the LimitReader used to guarantee.
		end := limit + 1
		if end > cap(buf) {
			end = cap(buf)
		}
		n, err := r.Read(buf[len(buf):end])
		buf = buf[:len(buf)+n]
		if err != nil {
			*bufp = buf
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
	*bufp = buf
	return nil
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

	// Bound the read: never exceed the 10MB hard cap. The buffer comes from
	// fetchBufPool and is grown in place, so a crawl of same-sized pages stops
	// allocating for the read entirely.
	bufp := getFetchBuf()
	if err := readAllInto(bufp, reader, maxBodyBytes); err != nil {
		// Nothing was observed by the caller, so returning the buffer here is
		// safe and keeps a failed fetch from leaking the pool's contents.
		putFetchBuf(bufp)
		return "", "", err
	}
	buf := *bufp
	if len(buf) > maxBodyBytes {
		buf = buf[:maxBodyBytes]
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Auto-detect encoding and convert to UTF-8
	charset := DetectEncoding(contentType, buf)
	utf8Body, _ := ConvertToUTF8(buf, charset)

	// string(utf8Body) is the copy boundary. ConvertToUTF8 hands back buf itself
	// for every charset it does not rewrite, so everything above this line —
	// DetectEncoding, ConvertToUTF8 and the string copy — is still reading the
	// pooled bytes, and the Put has to come after all of it. A Put here would let
	// whichever fetch Gets next rewrite bytes this one is still reading;
	// TestFetchURLConcurrentFetchesDoNotShareScratch is the guard, and it is not
	// a hazard the race detector shakes out on demand (§15 item 5).
	body := string(utf8Body)
	putFetchBuf(bufp)

	return body, contentType, nil
}
