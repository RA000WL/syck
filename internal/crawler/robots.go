package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/RA000WL/syck/internal/httpclient"
)

type robotsEntry struct {
	allow  bool
	prefix string
}

type robotsRule struct {
	entries    []robotsEntry
	crawlDelay time.Duration
	sitemaps   []string
}

// RobotsCache caches parsed robots.txt per domain.
type RobotsCache struct {
	mu     sync.Mutex
	cache  map[string]*robotsRule
	client *http.Client
	ua     string
}

func NewRobotsCache(client *http.Client, ua string) *RobotsCache {
	if client == nil {
		client = httpclient.NewClient(10*time.Second, "", false)
	}
	return &RobotsCache{
		cache:  make(map[string]*robotsRule),
		client: client,
		ua:     ua,
	}
}

// Allowed checks if a URL is allowed by robots.txt.
func (rc *RobotsCache) Allowed(rawURL string) bool {
	if rc == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	rule := rc.getOrCreate(u.Hostname())
	if rule == nil {
		return true
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	for _, entry := range rule.entries {
		if strings.HasPrefix(path, entry.prefix) {
			return entry.allow
		}
	}
	return true
}

// CrawlDelay returns the crawl delay for a domain.
func (rc *RobotsCache) CrawlDelay(rawURL string) time.Duration {
	if rc == nil {
		return 0
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	rule := rc.getOrCreate(u.Hostname())
	if rule == nil {
		return 0
	}
	return rule.crawlDelay
}

// Sitemaps returns the sitemap URLs declared in robots.txt for a domain.
func (rc *RobotsCache) Sitemaps(rawURL string) []string {
	if rc == nil {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	rule := rc.getOrCreate(u.Hostname())
	if rule == nil {
		return nil
	}
	return rule.sitemaps
}

func (rc *RobotsCache) getOrCreate(domain string) *robotsRule {
	rc.mu.Lock()
	if rule, ok := rc.cache[domain]; ok {
		rc.mu.Unlock()
		return rule
	}
	// Mark as "fetching" to prevent duplicate fetches
	rc.cache[domain] = nil
	rc.mu.Unlock()

	rule := rc.fetch(domain)

	rc.mu.Lock()
	rc.cache[domain] = rule
	rc.mu.Unlock()

	return rule
}

func (rc *RobotsCache) fetch(domain string) *robotsRule {
	rawURL := fmt.Sprintf("https://%s/robots.txt", domain)
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	ua := rc.ua
	if ua == "" {
		ua = "SyckBot/2.0 (+https://github.com/RA000WL/syck)"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/plain")

	resp, err := rc.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return nil
	}

	return parseRobotsTxt(string(body))
}

func parseRobotsTxt(content string) *robotsRule {
	lines := strings.Split(content, "\n")
	var rule robotsRule
	matchedAgent := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "user-agent":
			matchedAgent = (value == "*" || strings.Contains("syckbot", strings.ToLower(value)))
		case "disallow":
			if matchedAgent && value != "" {
				rule.entries = append(rule.entries, robotsEntry{allow: false, prefix: normalizePath(value)})
			}
		case "allow":
			if matchedAgent && value != "" {
				rule.entries = append(rule.entries, robotsEntry{allow: true, prefix: normalizePath(value)})
			}
		case "crawl-delay":
			if matchedAgent {
				if delay, err := time.ParseDuration(value + "s"); err == nil {
					rule.crawlDelay = delay
				}
			}
		case "sitemap":
			if value != "" {
				rule.sitemaps = append(rule.sitemaps, value)
			}
		}
	}

	if len(rule.entries) == 0 && rule.crawlDelay == 0 && len(rule.sitemaps) == 0 {
		return nil
	}
	return &rule
}

func normalizePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
