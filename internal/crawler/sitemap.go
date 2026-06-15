package crawler

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	MaxSitemapDepth      = 3
	MaxSitemapsPerDomain = 100
	MaxURLsFromSitemaps  = 10000
	maxSitemapBody       = 10 * 1024 * 1024 // 10 MB
)

// SitemapURL represents a single <url> entry in a sitemap.
type SitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod"`
	ChangeFreq string `xml:"changefreq"`
	Priority   string `xml:"priority"`
}

// SitemapURLSet is the root element of a standard sitemap.
type SitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []SitemapURL `xml:"url"`
}

// SitemapIndex is the root element of a sitemap index.
type SitemapIndex struct {
	XMLName  xml.Name `xml:"sitemapindex"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// ParseSitemap parses a standard sitemap XML and returns the URLs.
func ParseSitemap(data string) []SitemapURL {
	var urlset SitemapURLSet
	if err := xml.Unmarshal([]byte(data), &urlset); err != nil {
		return nil
	}
	return urlset.URLs
}

// ParseSitemapIndex parses a sitemap index XML and returns child sitemap URLs.
func ParseSitemapIndex(data string) []string {
	var index SitemapIndex
	if err := xml.Unmarshal([]byte(data), &index); err != nil {
		return nil
	}
	var urls []string
	for _, s := range index.Sitemaps {
		if s.Loc != "" {
			urls = append(urls, s.Loc)
		}
	}
	return urls
}

// SitemapFetcher fetches and parses sitemaps for a domain.
type SitemapFetcher struct {
	client *http.Client
	ua     string
}

// NewSitemapFetcher creates a SitemapFetcher with the given HTTP client and user agent.
func NewSitemapFetcher(client *http.Client, ua string) *SitemapFetcher {
	if ua == "" {
		ua = "SyckBot/2.0 (+https://github.com/RA000WL/syck)"
	}
	return &SitemapFetcher{client: client, ua: ua}
}

// standardSitemapPaths are the conventional sitemap locations to try if no robots.txt sitemaps found.
var standardSitemapPaths = []string{"/sitemap.xml", "/sitemap_index.xml"}

// FetchSitemaps fetches all sitemaps for a domain and returns discovered URLs.
// It processes robots.txt-declared sitemaps first, then tries standard paths if none found.
func (sf *SitemapFetcher) FetchSitemaps(domain string, robotsSitemaps []string) []string {
	if sf == nil {
		return nil
	}

	seen := make(map[string]bool)
	var allURLs []string

	// Build a set of standard paths that are already in robotsSitemaps
	robotsSet := make(map[string]bool)
	for _, s := range robotsSitemaps {
		robotsSet[s] = true
	}

	// Process robots.txt sitemaps first
	for _, sitemapURL := range robotsSitemaps {
		if len(allURLs) >= MaxURLsFromSitemaps {
			break
		}
		urls := sf.fetchAndParse(sitemapURL, seen, 0)
		allURLs = append(allURLs, urls...)
	}

	// If no sitemaps from robots.txt, try standard paths
	if len(robotsSitemaps) == 0 {
		for _, path := range standardSitemapPaths {
			if len(allURLs) >= MaxURLsFromSitemaps {
				break
			}
			sitemapURL := fmt.Sprintf("https://%s%s", domain, path)
			urls := sf.fetchAndParse(sitemapURL, seen, 0)
			allURLs = append(allURLs, urls...)
		}
	}

	return allURLs
}

// fetchAndParse fetches a sitemap URL, parses it, and recursively handles sitemap indices.
func (sf *SitemapFetcher) fetchAndParse(rawURL string, seen map[string]bool, depth int) []string {
	if depth > MaxSitemapDepth {
		return nil
	}
	if seen[rawURL] {
		return nil
	}
	seen[rawURL] = true

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", sf.ua)
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	resp, err := sf.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSitemapBody))
	if err != nil {
		return nil
	}

	content := string(body)

	// Check if this is a sitemap index
	childSitemaps := ParseSitemapIndex(content)
	if len(childSitemaps) > 0 {
		var allURLs []string
		for _, childURL := range childSitemaps {
			if len(allURLs) >= MaxURLsFromSitemaps {
				break
			}
			urls := sf.fetchAndParse(childURL, seen, depth+1)
			allURLs = append(allURLs, urls...)
		}
		return allURLs
	}

	// Parse as regular sitemap
	sitemapURLs := ParseSitemap(content)
	var urls []string
	for _, entry := range sitemapURLs {
		if entry.Loc != "" && !seen[entry.Loc] {
			seen[entry.Loc] = true
			urls = append(urls, entry.Loc)
		}
	}
	return urls
}

// isSitemapDomain returns true if the URL looks like it could be a sitemap.
func isSitemapDomain(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.HasSuffix(lower, ".xml") ||
		strings.HasSuffix(lower, ".xml.gz") ||
		strings.Contains(lower, "sitemap")
}
