package crawler

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

type CrawlConfig struct {
	Scope      *regexp.Regexp
	Limit      int
	MaxDepth   int
	Debug      bool
	HTTPClient *http.Client
}

type CrawledURL struct {
	URL         string
	Content     string
	ContentType string
	Depth       int
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

func Crawl(initialURLs []string, cfg CrawlConfig) []CrawledURL {
	if cfg.Limit <= 0 {
		cfg.Limit = 100
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}

	var results []CrawledURL
	visited := make(map[string]bool)
	type queueEntry struct {
		url   string
		depth int
	}
	var queue []queueEntry

	for _, u := range initialURLs {
		queue = append(queue, queueEntry{url: u, depth: 0})
	}

	for len(queue) > 0 && len(visited) < cfg.Limit {
		entry := queue[0]
		queue = queue[1:]

		if visited[entry.url] {
			continue
		}
		if entry.depth > cfg.MaxDepth {
			continue
		}
		if cfg.Scope != nil && !cfg.Scope.MatchString(entry.url) {
			continue
		}

		visited[entry.url] = true
		content, contentType, err := fetchURL(client, entry.url)
		if err != nil {
			if cfg.Debug {
				fmt.Printf("[debug] fetch %s: %v\n", entry.url, err)
			}
			continue
		}

		results = append(results, CrawledURL{
			URL:         entry.url,
			Content:     content,
			ContentType: contentType,
			Depth:       entry.depth,
		})

		if entry.depth < cfg.MaxDepth && len(visited) < cfg.Limit {
			base, _ := url.Parse(entry.url)
			newURLs := ExtractURLs(content, base, contentType)
			for _, nu := range newURLs {
				if !visited[nu] {
					queue = append(queue, queueEntry{url: nu, depth: entry.depth + 1})
				}
			}
		}
	}

	return results
}

func fetchURL(client *http.Client, rawURL string) (string, string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "syck/2.0.0")
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

	return string(body), contentType, nil
}
