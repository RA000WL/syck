package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// WaybackResult holds a historical URL from the Wayback Machine.
type WaybackResult struct {
	URL       string
	Timestamp string
	Status    string
	MimeType  string
}

// FetchWaybackURLs queries the Wayback Machine CDX API for historical URLs.
func FetchWaybackURLs(domain string, client *http.Client, limit int) ([]WaybackResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	// CDX API query — match all URLs under the domain
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=%d",
		domain, limit)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("wayback request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50MB limit
	if err != nil {
		return nil, fmt.Errorf("wayback read: %w", err)
	}

	// CDX returns JSON array of arrays: [["url","timestamp","status","mime"], ...]
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback parse: %w", err)
	}

	if len(rows) < 2 {
		return nil, nil // empty or header-only
	}

	// Skip header row (first element)
	domainLower := strings.ToLower(domain)
	var results []WaybackResult
	seen := make(map[string]bool)

	for _, row := range rows[1:] {
		if len(row) < 4 {
			continue
		}
		rawURL := row[0]
		ts := row[1]
		status := row[2]
		mime := row[3]

		// Only include successful responses
		if status != "200" && status != "301" && status != "302" {
			continue
		}

		// Skip non-text content types
		if !isTextMime(mime) {
			continue
		}

		// Normalize URL
		cleanURL := normalizeWaybackURL(rawURL)
		if cleanURL == "" {
			continue
		}

		// Must be under the target domain
		if !strings.HasSuffix(strings.ToLower(cleanURL), "."+domainLower) &&
			!strings.Contains(strings.ToLower(cleanURL), domainLower) {
			continue
		}

		if seen[cleanURL] {
			continue
		}
		seen[cleanURL] = true

		results = append(results, WaybackResult{
			URL:       cleanURL,
			Timestamp: ts,
			Status:    status,
			MimeType:  mime,
		})
	}

	return results, nil
}

// normalizeWaybackURL strips the Wayback Machine prefix and normalizes the URL.
func normalizeWaybackURL(raw string) string {
	// Remove wayback prefix: http://web.archive.org/web/20240101/https://example.com/path
	re := regexp.MustCompile(`^https?://web\.archive\.org/web/\d+/(https?://.+)`)
	if m := re.FindStringSubmatch(raw); len(m) > 1 {
		return m[1]
	}
	// Already a clean URL
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return ""
}

// isTextMime checks if a MIME type represents text-based content.
func isTextMime(mime string) bool {
	textTypes := []string{
		"text/html", "text/plain", "text/css", "text/javascript",
		"application/javascript", "application/json", "application/xml",
		"application/x-javascript", "text/xml", "text/json",
		"application/xhtml+xml", "application/rss+xml", "application/atom+xml",
	}
	mime = strings.ToLower(mime)
	for _, t := range textTypes {
		if strings.HasPrefix(mime, t) {
			return true
		}
	}
	return false
}
