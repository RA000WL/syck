package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/RA000WL/syck/internal/finding"
)

var defaultJuicyPaths = []string{
	"/.env", "/.env.local", "/.env.production", "/.env.development",
	"/config.json", "/config.yaml", "/config.yml",
	"/swagger.json", "/openapi.json", "/openapi.yaml",
	"/api-docs", "/v3/api-docs", "/v2/api-docs",
	"/actuator", "/actuator/env", "/actuator/configprops", "/actuator/beans", "/actuator/mappings",
	"/metrics", "/prometheus", "/health", "/info",
	"/server-status", "/server-info",
	"/crossdomain.xml", "/.htaccess", "/.git/HEAD", "/.git/config",
	"/robots.txt", "/sitemap.xml",
	"/phpinfo.php", "/info.php", "/test.php",
	"/admin", "/administrator", "/wp-admin", "/wp-login.php",
	"/elmah.axd", "/trace.axd",
}

const maxJuicyBodyBytes = 1 << 20

type JuicyConfig struct {
	Client    *http.Client
	BaseURL   string
	Paths     []string
	UserAgent string
}

type JuicyFinding struct {
	URL         string
	Path        string
	ContentType string
	Body        string
}

func ProbeJuicy(cfg JuicyConfig) []JuicyFinding {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * 1e9}
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil
	}
	paths := cfg.Paths
	if len(paths) == 0 {
		paths = defaultJuicyPaths
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []JuicyFinding
		limit   = make(chan struct{}, 5)
	)

	for _, p := range paths {
		target := *base
		target.Path = strings.TrimRight(base.Path, "/") + p
		raw := target.String()

		wg.Add(1)
		limit <- struct{}{}
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-limit }()

			ua := cfg.UserAgent
			if ua == "" {
				ua = "syck/1.1"
			}

			req, _ := http.NewRequest("HEAD", rawURL, nil)
			req.Header.Set("User-Agent", ua)
			resp, err := cfg.Client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return
			}
			contentType := resp.Header.Get("Content-Type")

			req2, _ := http.NewRequest("GET", rawURL, nil)
			req2.Header.Set("User-Agent", ua)
			resp2, err := cfg.Client.Do(req2)
			if err != nil {
				return
			}
			defer resp2.Body.Close()
			if resp2.ContentLength > maxJuicyBodyBytes {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, maxJuicyBodyBytes+1))
			if len(body) > maxJuicyBodyBytes {
				return
			}

			mu.Lock()
			results = append(results, JuicyFinding{
				URL:         rawURL,
				Path:        p,
				ContentType: contentType,
				Body:        string(body),
			})
			mu.Unlock()
		}(raw)
	}
	wg.Wait()
	return results
}

func (j JuicyFinding) ToFinding() finding.Finding {
	return finding.Finding{
		File:     j.URL,
		Line:     1,
		Column:   0,
		RuleName: "juicy_file",
		Severity: finding.SeverityMedium,
		Secret:   fmt.Sprintf("%s [%s]", j.Path, j.ContentType),
		Context:  truncate(j.Body, 200),
		Entropy:  0.0,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
