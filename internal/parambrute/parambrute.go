// Package parambrute provides hidden parameter discovery via brute-force.
package parambrute

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// RateLimiter provides per-host rate limiting
type RateLimiter struct {
	mu       sync.Mutex
	lastTime map[string]time.Time
	minGap   time.Duration
}

// NewRateLimiter creates a rate limiter with requests per second limit
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{
		lastTime: make(map[string]time.Time),
		minGap:   time.Second / time.Duration(rps),
	}
}

// Wait blocks until a request can be made for the given host
func (r *RateLimiter) Wait(host string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if last, ok := r.lastTime[host]; ok {
		wait := r.minGap - time.Since(last)
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	r.lastTime[host] = time.Now()
}

// Common parameter wordlist for brute-force discovery
var commonParams = []string{
	// Authentication & Authorization
	"api_key", "apikey", "api-key", "token", "access_token", "auth",
	"authorization", "bearer", "credentials", "password", "secret",
	"session", "session_id", "sessionid", "jwt", "oauth_token",
	"client_id", "client_secret", "refresh_token",

	// Admin & Debug
	"admin", "debug", "test", "dev", "mode", "internal",
	"preview", "draft", "sandbox", "flag", "feature",
	"toggle", "switch", "override",

	// Data & Filtering
	"page", "per_page", "limit", "offset", "skip", "count",
	"search", "query", "q", "filter", "sort", "order",
	"fields", "select", "include", "exclude", "expand",

	// IDs & References
	"id", "user_id", "userid", "user-id", "account_id",
	"order_id", "product_id", "item_id", "record_id",
	"parent_id", "owner_id", "created_by",

	// File & Upload
	"file", "filename", "filepath", "path", "directory",
	"upload", "attachment", "document", "image", "avatar",

	// Database & SQL
	"table", "column", "database", "db", "schema",
	"query", "sql", "join", "where", "select",

	// Injection Testing
	"callback", "redirect", "return_to", "next", "url",
	"continue", "dest", "destination", "redir", "redirect_uri",
	"return", "goto", "exit", "to",

	// API & Versioning
	"version", "v", "api_version", "format", "type",
	"action", "method", "operation", "command",

	// Pagination
	"cursor", "before", "after", "start", "end",
	"next_page", "prev_page", "page_token",

	// Common Hidden
	"token", "key", "hash", "signature", "sign",
	"nonce", "timestamp", "date", "time",
	"ip", "user_agent", "referrer", "origin",
	"host", "domain", "subdomain",

	// Config & Settings
	"config", "settings", "options", "params",
	"attributes", "properties", "metadata", "meta",

	// Logging & Monitoring
	"log", "log_level", "verbose", "debug_level",
	"trace", "profile", "metric", "stats",

	// Misc
	"lang", "locale", "language", "country", "region",
	"theme", "style", "css", "js", "minify",
	"cache", "nocache", "purge", "refresh",
}

// ParamFinding represents a discovered parameter
type ParamFinding struct {
	URL          string
	Parameter    string
	StatusCode   int
	ResponseSize int
	Reflected    bool
	Interesting  bool
	Reason       string
}

// Config for parameter brute-force
type Config struct {
	Client      *http.Client
	Concurrency int
	Timeout     time.Duration
	Wordlist    []string
	MaxParams   int
	RateLimit   int  // requests per second per host (0 = unlimited)
	RetryCount  int  // number of retries on 429
	RetryDelay  time.Duration // delay between retries
}

// DefaultConfig returns a default configuration
func DefaultConfig(client *http.Client) Config {
	return Config{
		Client:      client,
		Concurrency: 10,
		Timeout:     10 * time.Second,
		Wordlist:    commonParams,
		MaxParams:   500,
		RateLimit:   10,
		RetryCount:  3,
		RetryDelay:  1 * time.Second,
	}
}

// BruteForce discovers hidden parameters on a URL
func BruteForce(rawURL string, cfg Config) []ParamFinding {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: cfg.Timeout}
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if len(cfg.Wordlist) == 0 {
		cfg.Wordlist = commonParams
	}
	if cfg.MaxParams > 0 && len(cfg.Wordlist) > cfg.MaxParams {
		cfg.Wordlist = cfg.Wordlist[:cfg.MaxParams]
	}

	// Parse the base URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	// Get baseline response
	baseline := getBaseline(cfg.Client, rawURL)
	if baseline == nil {
		return nil
	}

	// Create rate limiter
	var rateLimiter *RateLimiter
	if cfg.RateLimit > 0 {
		rateLimiter = NewRateLimiter(cfg.RateLimit)
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []ParamFinding
		sem     = make(chan struct{}, cfg.Concurrency)
	)

	for _, param := range cfg.Wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			finding := testParameter(cfg.Client, parsed, p, baseline, rateLimiter, cfg.RetryCount, cfg.RetryDelay)
			if finding != nil {
				mu.Lock()
				results = append(results, *finding)
				mu.Unlock()
			}
		}(param)
	}

	wg.Wait()

	// Sort by interestingness (interesting first, then by status code)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Interesting != results[j].Interesting {
			return results[i].Interesting
		}
		return results[i].StatusCode < results[j].StatusCode
	})

	return results
}

type baseline struct {
	StatusCode   int
	ResponseSize int
	Body         string
}

func getBaseline(client *http.Client, rawURL string) *baseline {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "syck-parambrute/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	return &baseline{
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
		Body:         string(body),
	}
}

func testParameter(client *http.Client, base *url.URL, param string, bl *baseline, rateLimiter *RateLimiter, retryCount int, retryDelay time.Duration) *ParamFinding {
	// Wait for rate limiter
	if rateLimiter != nil {
		rateLimiter.Wait(base.Hostname())
	}

	// Test with GET parameter
	testURL := *base
	q := testURL.Query()
	q.Set(param, "test123")
	testURL.RawQuery = q.Encode()

	var lastErr error
	for attempt := 0; attempt <= retryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay * time.Duration(attempt))
			if rateLimiter != nil {
				rateLimiter.Wait(base.Hostname())
			}
		}

		req, err := http.NewRequest("GET", testURL.String(), nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "syck-parambrute/1.0")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Handle rate limiting (429)
		if resp.StatusCode == 429 {
			resp.Body.Close()
			lastErr = fmt.Errorf("rate limited (429)")
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		bodyStr := string(body)

		finding := &ParamFinding{
			URL:          base.String(),
			Parameter:    param,
			StatusCode:   resp.StatusCode,
			ResponseSize: len(body),
		}

		// Check if parameter is reflected in response
		finding.Reflected = strings.Contains(bodyStr, "test123")

		// Determine if finding is interesting
		finding.Interesting, finding.Reason = isInteresting(resp.StatusCode, len(body), bl, finding.Reflected)

		if !finding.Interesting {
			return nil
		}

		return finding
	}

	// All retries failed
	if lastErr != nil && retryCount > 0 {
		// Silently ignore after retries
	}

	return nil
}

func isInteresting(statusCode, responseSize int, bl *baseline, reflected bool) (bool, string) {
	// Status code changed from baseline
	if statusCode != bl.StatusCode {
		return true, fmt.Sprintf("status code changed: %d → %d", bl.StatusCode, statusCode)
	}

	// Response size changed significantly (>10% difference)
	sizeDiff := abs(responseSize - bl.ResponseSize)
	threshold := bl.ResponseSize / 10
	if threshold < 50 {
		threshold = 50
	}
	if sizeDiff > threshold {
		return true, fmt.Sprintf("response size changed: %d → %d", bl.ResponseSize, responseSize)
	}

	// Parameter value reflected in response
	if reflected {
		return true, "parameter value reflected in response"
	}

	return false, ""
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// InterestingPatterns are patterns that indicate a parameter might be exploitable
var InterestingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(error|exception|warning|stack|trace|debug)`),
	regexp.MustCompile(`(?i)(sql|mysql|postgres|oracle|sqlite)`),
	regexp.MustCompile(`(?i)(root|admin|superuser|password|credential)`),
	regexp.MustCompile(`(?i)(file|path|directory|folder|upload)`),
	regexp.MustCompile(`(?i)(internal|private|secret|hidden)`),
}
