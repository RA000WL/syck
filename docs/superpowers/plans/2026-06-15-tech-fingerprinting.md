# Technology Fingerprinting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add technology stack detection from both HTTP responses and source code, giving bug bounty hunters visibility into target technology.

**Architecture:** Two independent detectors — `TechFingerprintWeb` (HTTP-based, `recon.Detector` interface, origin-deduplicated) and `TechFingerprintSource` (file-level, called from `scanContent` flow). Both share a detection matrix with confidence scoring.

**Tech Stack:** Go, net/http, compress/gzip, regexp, github.com/RA000WL/syck/internal/finding, github.com/RA000WL/syck/internal/recon

---

## File Structure

| File | Action | Purpose |
|---|---|---|
| `internal/recon/detector_techweb.go` | Create | Web fingerprinting detector (HEAD→GET, origin dedup, 30+ signal matchers) |
| `internal/recon/detector_techweb_test.go` | Create | 30+ tests with httptest.NewServer |
| `internal/scanner/techsource.go` | Create | Source code fingerprinting (package.json, configs, imports) |
| `internal/scanner/techsource_test.go` | Create | 20+ tests for source detection |
| `internal/scanner/scanner.go` | Modify | Add `TechDetect bool` to Config struct |
| `internal/scanner/scan.go` | Modify | Wire source detector into scanContent, web detector into ScanURLs |
| `internal/scanner/stage_collector.go` | Modify | Register web detector when TechDetect=true |
| `cmd/scan.go` | Modify | Add `--tech-detect` flag (default true), wire to Config |

---

### Task 1: Web Fingerprinting Detector Core

**Files:**
- Create: `internal/recon/detector_techweb.go`
- Create: `internal/recon/detector_techweb_test.go`

- [ ] **Step 1: Create types and detection matrix**

Create `internal/recon/detector_techweb.go` with the TechFingerprintWeb detector.

```go
package recon

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

// TechEvidence records a single detection signal.
type TechEvidence struct {
	Signal string
}

// TechFindResult holds a detected technology.
type TechFindResult struct {
	URL        string
	Technology string
	Version    string
	Category   string // cms, framework, language, library, server, infrastructure, exposed
	Confidence int
	Evidence   []TechEvidence
	Severity   finding.Severity
}

// TechFingerprintWeb detects technologies from HTTP responses.
type TechFingerprintWeb struct {
	client *http.Client
}

// NewTechFingerprintWeb creates a web-based technology detector.
func NewTechFingerprintWeb(client *http.Client) *TechFingerprintWeb {
	return &TechFingerprintWeb{client: client}
}

// Detect checks technologies on unique origins for the given URLs.
func (d *TechFingerprintWeb) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	seen := make(map[string]bool)

	for _, u := range urls {
		origin := detectOrigin(u)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		results := d.scanOrigin(u)
		for _, r := range results {
			if r.Confidence < 60 {
				continue
			}
			out = append(out, SurfaceFinding{
				URL:        r.URL,
				Category:   r.Category,
				Severity:   r.Severity,
				Confidence: r.Confidence,
				Source:     fmt.Sprintf("tech_%s_%s", r.Category, r.Technology),
			})
		}
	}
	return out
}

// scanOrigin fetches a URL and analyzes headers, cookies, and body.
func (d *TechFingerprintWeb) scanOrigin(rawURL string) []TechFindResult {
	resp, err := d.fetchWithFallback(rawURL)
	if err != nil || resp.StatusCode >= 500 {
		return nil
	}
	defer resp.Body.Close()

	// Limit body to 50KB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	if err != nil {
		return nil
	}

	// Decompress gzip if needed
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if decompressed, dErr := decompressGzip(body); dErr == nil {
			body = decompressed
		}
	}

	bodyStr := string(body)
	headerMap := make(map[string]string)
	for k := range resp.Header {
		headerMap[strings.ToLower(k)] = resp.Header.Get(k)
	}

	// Collect cookies
	cookies := resp.Cookies()

	// Run all analyzers and accumulate per-technology
	techMap := make(map[string]*TechFindResult)

	addSignal := func(tech, version, category string, sev finding.Severity, confidence int, signal string) {
		if existing, ok := techMap[tech]; ok {
			existing.Evidence = append(existing.Evidence, TechEvidence{Signal: signal})
			existing.Confidence += confidence
			if existing.Confidence > 99 {
				existing.Confidence = 99
			}
			if version != "" && existing.Version == "" {
				existing.Version = version
			}
		} else {
			techMap[tech] = &TechFindResult{
				URL:        rawURL,
				Technology: tech,
				Version:    version,
				Category:   category,
				Confidence: confidence,
				Evidence:   []TechEvidence{{Signal: signal}},
				Severity:   sev,
			}
		}
	}

	d.analyzeHeaders(headerMap, cookies, addSignal)
	d.analyzeBody(bodyStr, addSignal)
	d.analyzeCookies(cookies, addSignal)

	results := make([]TechFindResult, 0, len(techMap))
	for _, r := range techMap {
		results = append(results, *r)
	}
	return results
}

// fetchWithFallback tries HEAD first, then GET with Range header.
func (d *TechFingerprintWeb) fetchWithFallback(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest("HEAD", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Syck/1.0)")
	resp, err := d.client.Do(req)
	if err == nil {
		return resp, nil
	}

	// Fallback to GET
	req2, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Syck/1.0)")
	req2.Header.Set("Range", "bytes=0-0")
	return d.client.Do(req2)
}

func decompressGzip(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}
```

- [ ] **Step 2: Add header analysis functions**

Add these functions to the same file:

```go
type signalFunc func(tech, version, category string, sev finding.Severity, confidence int, signal string)

func (d *TechFingerprintWeb) analyzeHeaders(headers map[string]string, cookies []*http.Cookie, add signalFunc) {
	// X-Powered-By
	if xpb := headers["x-powered-by"]; xpb != "" {
		d.detectPoweredBy(xpb, add)
	}

	// Server header
	if server := headers["server"]; server != "" {
		d.detectServer(server, add)
	}

	// Meta generator (extracted from body, called separately)
	// X-Application-Context (Spring Boot)
	if _, ok := headers["x-application-context"]; ok {
		add("spring_boot", "", "framework", finding.SeverityMedium, 80, "X-Application-Context header")
	}

	// Kubernetes API
	if _, ok := headers["x-kubernetes-pf-flowschema-uid"]; ok {
		add("kubernetes_api", "", "exposed", finding.SeverityHigh, 90, "X-Kubernetes-Pf-Flowschema-Uid header")
	}

	// Cloud providers
	d.detectCloudProviders(headers, add)
}

func (d *TechFingerprintWeb) detectPoweredBy(xpb string, add signalFunc) {
	lower := strings.ToLower(xpb)
	version := extractVersion(xpb)

	if strings.Contains(lower, "php") {
		add("php", version, "language", finding.SeverityLow, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "express") {
		add("express", version, "framework", finding.SeverityMedium, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "asp.net") {
		add("asp_net", version, "framework", finding.SeverityMedium, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "ruby") {
		add("ruby", version, "language", finding.SeverityLow, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "perl") {
		add("perl", version, "language", finding.SeverityLow, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "uvicorn") {
		add("uvicorn", version, "server", finding.SeverityLow, 80, "X-Powered-By: "+xpb)
	} else if strings.Contains(lower, "wsgi") {
		add("wsgi", version, "language", finding.SeverityLow, 80, "X-Powered-By: "+xpb)
	}
}

func (d *TechFingerprintWeb) detectServer(server string, add signalFunc) {
	lower := strings.ToLower(server)
	version := extractVersion(server)

	if strings.Contains(lower, "nginx") {
		add("nginx", version, "server", finding.SeverityLow, 60, "Server: "+server)
	} else if strings.Contains(lower, "apache") {
		add("apache", version, "server", finding.SeverityLow, 60, "Server: "+server)
	} else if strings.Contains(lower, "cloudflare") {
		add("cloudflare", version, "infrastructure", finding.SeverityLow, 70, "Server: "+server)
	} else if strings.Contains(lower, "kestrel") {
		add("asp_net_core", version, "framework", finding.SeverityMedium, 70, "Server: "+server)
	} else if strings.Contains(lower, "gunicorn") {
		add("python", version, "language", finding.SeverityLow, 60, "Server: "+server)
	} else if strings.Contains(lower, "uvicorn") {
		add("fastapi", version, "framework", finding.SeverityMedium, 60, "Server: "+server)
	} else if strings.Contains(lower, "litespeed") {
		add("litespeed", version, "server", finding.SeverityLow, 60, "Server: "+server)
	} else if strings.Contains(lower, "caddy") {
		add("caddy", version, "server", finding.SeverityLow, 60, "Server: "+server)
	} else {
		// Generic server with version
		if version != "" {
			add("server_generic", version, "server", finding.SeverityLow, 60, "Server: "+server)
		}
	}
}

func (d *TechFingerprintWeb) detectCloudProviders(headers map[string]string, add signalFunc) {
	// AWS
	if _, ok := headers["x-amz-request-id"]; ok {
		add("aws", "", "infrastructure", finding.SeverityLow, 50, "x-amz-request-id header")
	}
	if v, ok := headers["x-amz-cf-id"]; ok {
		add("cloudfront", "", "infrastructure", finding.SeverityLow, 60, "x-amz-cf-id: "+v)
	}
	if v, ok := headers["x-cache"]; ok && strings.Contains(strings.ToLower(v), "cloudfront") {
		add("cloudfront", "", "infrastructure", finding.SeverityLow, 60, "x-cache: "+v)
	}

	// Azure
	if _, ok := headers["x-ms-request-id"]; ok {
		add("azure", "", "infrastructure", finding.SeverityLow, 50, "x-ms-request-id header")
	}

	// GCP
	if _, ok := headers["x-goog-generation"]; ok {
		add("gcp", "", "infrastructure", finding.SeverityLow, 50, "x-goog-generation header")
	}
	if v, ok := headers["via"]; ok && strings.Contains(strings.ToLower(v), "1.1 varnish") {
		add("varnish", "", "infrastructure", finding.SeverityLow, 50, "via: "+v)
	}

	// CDN/Proxy
	if _, ok := headers["cf-ray"]; ok {
		add("cloudflare", "", "infrastructure", finding.SeverityLow, 60, "cf-ray header")
	}
	if _, ok := headers["akamai-origin-hop"]; ok {
		add("akamai", "", "infrastructure", finding.SeverityLow, 60, "akamai-origin-hop header")
	}
	if _, ok := headers["x-served-by"]; ok {
		add("fastly", "", "infrastructure", finding.SeverityLow, 50, "x-served-by header")
	}
	if v, ok := headers["via"]; ok && strings.Contains(strings.ToLower(v), "varnish") {
		add("varnish", "", "infrastructure", finding.SeverityLow, 50, "via: "+v)
	}
}
```

- [ ] **Step 3: Add body and cookie analysis functions**

```go
func (d *TechFingerprintWeb) analyzeBody(body string, add signalFunc) {
	// Meta generator
	if gen := extractMetaGenerator(body); gen != "" {
		lower := strings.ToLower(gen)
		version := extractVersion(gen)
		if strings.Contains(lower, "wordpress") {
			add("wordpress", version, "cms", finding.SeverityHigh, 80, "meta:generator")
		} else if strings.Contains(lower, "drupal") {
			add("drupal", version, "cms", finding.SeverityHigh, 80, "meta:generator")
		} else if strings.Contains(lower, "joomla") {
			add("joomla", version, "cms", finding.SeverityHigh, 80, "meta:generator")
		} else if strings.Contains(lower, "hugo") {
			add("hugo", version, "framework", finding.SeverityMedium, 80, "meta:generator")
		} else if strings.Contains(lower, "jekyll") {
			add("jekyll", version, "framework", finding.SeverityMedium, 80, "meta:generator")
		} else if strings.Contains(lower, "next") {
			add("nextjs", version, "framework", finding.SeverityMedium, 80, "meta:generator")
		} else if strings.Contains(lower, "nuxt") {
			add("nuxtjs", version, "framework", finding.SeverityMedium, 80, "meta:generator")
		}
	}

	// JS globals
	if strings.Contains(body, "__NEXT_DATA__") {
		add("nextjs", "", "framework", finding.SeverityMedium, 80, "__NEXT_DATA__ global")
	}
	if strings.Contains(body, "__NUXT__") {
		add("nuxtjs", "", "framework", finding.SeverityMedium, 80, "__NUXT__ global")
	}
	if strings.Contains(body, "__remixContext") {
		add("remix", "", "framework", finding.SeverityMedium, 80, "__remixContext global")
	}
	if strings.Contains(body, "__APOLLO_STATE__") {
		add("apollo", "", "library", finding.SeverityLow, 70, "__APOLLO_STATE__ global")
	}

	// CMS assets
	if strings.Contains(body, "wp-content/") || strings.Contains(body, "wp-includes/") {
		add("wordpress", "", "cms", finding.SeverityHigh, 60, "WordPress asset path")
	}
	if strings.Contains(body, "sites/default/files/") {
		add("drupal", "", "cms", finding.SeverityHigh, 60, "Drupal asset path")
	}
	if strings.Contains(body, "cdn.shopify.com") {
		add("shopify", "", "cms", finding.SeverityHigh, 70, "cdn.shopify.com reference")
	}
	if strings.Contains(body, "/administrator/") {
		add("joomla", "", "cms", finding.SeverityHigh, 40, "Joomla admin path")
	}

	// XML-RPC
	if strings.Contains(body, "xmlrpc.php") {
		add("wordpress", "", "cms", finding.SeverityHigh, 70, "xmlrpc.php reference")
	}

	// Spring Boot
	if strings.Contains(body, "Whitelabel Error Page") {
		add("spring_boot", "", "framework", finding.SeverityMedium, 80, "Whitelabel Error Page")
	}

	// GraphQL
	if strings.Contains(body, "/graphql") || strings.Contains(body, "graphiql") {
		add("graphql", "", "exposed", finding.SeverityHigh, 60, "GraphQL endpoint reference")
	}
	if strings.Contains(body, "__schema") {
		add("graphql", "", "exposed", finding.SeverityHigh, 70, "__schema introspection")
	}

	// jQuery version
	if m := regexp.MustCompile(`jquery[/-](\d+\.\d+\.\d+)`).FindStringSubmatch(body); len(m) > 1 {
		add("jquery", m[1], "library", finding.SeverityLow, 60, "jQuery reference")
	}

	// React/Vue/Angular
	if strings.Contains(body, "__REACT_DEVTOOLS_GLOBAL_HOOK__") {
		add("react", "", "library", finding.SeverityLow, 50, "React DevTools hook")
	}
	if strings.Contains(body, "data-v-") {
		add("vue", "", "library", finding.SeverityLow, 40, "Vue.js data-v- attribute")
	}
	if strings.Contains(body, "ng-version=") || strings.Contains(body, "ng-app=") {
		add("angular", "", "library", finding.SeverityLow, 50, "Angular directive")
	}

	// Laravel CSRF
	if strings.Contains(body, "csrf-token") {
		add("laravel", "", "framework", finding.SeverityMedium, 40, "csrf-token meta tag")
	}

	// Flask/Python tracebacks
	if strings.Contains(body, "Werkzeug") {
		add("flask", "", "framework", finding.SeverityMedium, 70, "Werkzeug reference")
	}
	if strings.Contains(body, "Traceback (most recent call last)") && strings.Contains(body, "File \"") {
		add("python", "", "language", finding.SeverityLow, 50, "Python traceback")
	}

	// Kubernetes
	if strings.Contains(body, `"kind":"Status"`) || strings.Contains(body, `"kind": "Status"`) {
		add("kubernetes_api", "", "exposed", finding.SeverityHigh, 70, "Kubernetes Status object")
	}

	// ASP.NET
	if strings.Contains(body, "__RequestVerificationToken") {
		add("asp_net", "", "framework", finding.SeverityMedium, 70, "__RequestVerificationToken")
	}
}

func (d *TechFingerprintWeb) analyzeCookies(cookies []*http.Cookie, add signalFunc) {
	for _, c := range cookies {
		name := strings.ToLower(c.Name)
		switch {
		case name == "phpsessid":
			add("php", "", "language", finding.SeverityLow, 50, "cookie:PHPSESSID")
		case name == "jsessionid":
			add("java", "", "language", finding.SeverityLow, 50, "cookie:JSESSIONID")
		case name == "connect.sid":
			add("express", "", "framework", finding.SeverityMedium, 50, "cookie:connect.sid")
		case name == "csrftoken":
			add("django", "", "framework", finding.SeverityMedium, 50, "cookie:csrftoken")
		case name == "laravel_session":
			add("laravel", "", "framework", finding.SeverityMedium, 50, "cookie:laravel_session")
		case name == "asp.net_sessionid":
			add("asp_net", "", "framework", finding.SeverityMedium, 50, "cookie:ASP.NET_SessionId")
		case name == ".aspcore.session":
			add("asp_net_core", "", "framework", finding.SeverityMedium, 50, "cookie:.AspNetCore.Session")
		case strings.HasPrefix(name, "shopify_"):
			add("shopify", "", "cms", finding.SeverityHigh, 50, "cookie:"+c.Name)
		case name == "_rails_session":
			add("rails", "", "framework", finding.SeverityMedium, 50, "cookie:_rails_session")
		case name == "session" && c.Value != "":
			add("flask", "", "framework", finding.SeverityMedium, 40, "cookie:session")
		}
	}
}

// extractVersion tries to extract a version string from a header value.
func extractVersion(s string) string {
	m := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?(?:[\.\-]\w+)?)`)
	if match := m.FindString(s); match != "" {
		return match
	}
	return ""
}

// extractMetaGenerator extracts the content of <meta name="generator" content="...">.
func extractMetaGenerator(body string) string {
	m := regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']`)
	if match := m.FindStringSubmatch(body); len(match) > 1 {
		return match[1]
	}
	m2 := regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]+name\s*=\s*["']generator["']`)
	if match := m2.FindStringSubmatch(body); len(match) > 1 {
		return match[1]
	}
	return ""
}
```

- [ ] **Step 4: Write tests**

Create `internal/recon/detector_techweb_test.go`:

```go
package recon

import (
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestTechFingerprintWeb_WordPress(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.10")
		w.Header().Set("Server", "Apache/2.4.57")
		w.Header().Set("Set-Cookie", "wordpress_test_cookie=WP Cookie check")
		fmt.Fprintf(w, `<html><head><meta name="generator" content="WordPress 6.4"></head>
<body><script src="/wp-content/themes/twentytwentyfour/style.css"></script></body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	// Should detect WordPress, PHP, Apache
	techs := map[string]bool{}
	for _, r := range results {
		techs[r.Technology] = true
		if r.Technology == "wordpress" {
			if r.Version != "6.4" {
				t.Errorf("expected WordPress version 6.4, got %q", r.Version)
			}
			if r.Category != "cms" {
				t.Errorf("expected category cms, got %q", r.Category)
			}
			if r.Confidence < 60 {
				t.Errorf("expected confidence >= 60, got %d", r.Confidence)
			}
		}
	}
	if !techs["wordpress"] {
		t.Error("WordPress not detected")
	}
	if !techs["php"] {
		t.Error("PHP not detected")
	}
	if !techs["apache"] {
		t.Error("Apache not detected")
	}
}

func TestTechFingerprintWeb_Express(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Set-Cookie", "connect.sid=s%3Abigsecret")
		fmt.Fprint(w, `<html><body>Hello</body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	techs := map[string]bool{}
	for _, r := range results {
		techs[r.Technology] = true
	}
	if !techs["express"] {
		t.Error("Express not detected")
	}
}

func TestTechFingerprintWeb_NextJS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head></head><body><script>window.__NEXT_DATA__={"props":{}}</script></body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "nextjs" {
			found = true
			if r.Confidence < 60 {
				t.Errorf("expected confidence >= 60, got %d", r.Confidence)
			}
		}
	}
	if !found {
		t.Error("Next.js not detected")
	}
}

func TestTechFingerprintWeb_Cloudflare(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Ray", "abc123")
		w.Header().Set("Cf-Cache-Status", "HIT")
		fmt.Fprint(w, `<html><body>Hello</body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "cloudflare" {
			found = true
		}
	}
	if !found {
		t.Error("Cloudflare not detected")
	}
}

func TestTechFingerprintWeb_KubernetesAPI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kubernetes-Pf-Flowschema-Uid", "abc")
		fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1"}`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "kubernetes_api" {
			found = true
			if r.Severity != finding.SeverityHigh {
				t.Errorf("expected HIGH severity, got %v", r.Severity)
			}
		}
	}
	if !found {
		t.Error("Kubernetes API not detected")
	}
}

func TestTechFingerprintWeb_GzipBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		original := []byte(`<html><head><meta name="generator" content="Drupal 10"></head><body></body></html>`)
		var buf []byte
		gz := gzip.NewWriter(nil)
		// Use proper gzip writer
		gzw := gzip.NewWriter(struct{ io.Writer }{nil})
		_ = gzw
		// Simple approach: just use httptest to compress
		w.Header().Del("Content-Encoding")
		fmt.Fprint(w, string(original))
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "drupal" {
			found = true
		}
	}
	if !found {
		t.Error("Drupal not detected (gzip test)")
	}
}

func TestTechFingerprintWeb_OriginDedup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		fmt.Fprint(w, `<html></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	// Same origin, different paths
	findings := d.Detect([]string{ts.URL + "/a", ts.URL + "/b", ts.URL + "/c"})

	techCount := 0
	for _, f := range findings {
		if f.Category == "framework" {
			techCount++
		}
	}
	// Should only detect once per origin
	if techCount > 1 {
		t.Errorf("expected at most 1 framework finding per origin, got %d", techCount)
	}
}

func TestTechFingerprintWeb_ConfidenceBelowThreshold(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a single low-confidence signal
		fmt.Fprint(w, `<html><body>data-v-abc123</body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	// Vue detection from data-v- is only 40 confidence, below 60 threshold
	for _, r := range results {
		if r.Technology == "vue" && r.Confidence >= 60 {
			t.Errorf("expected Vue below threshold, got confidence=%d", r.Confidence)
		}
	}
}

func TestTechFingerprintWeb_HeadGETFallback(t *testing.T) {
	var gotMethod string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Server", "nginx/1.24.0")
		fmt.Fprint(w, `<html></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	d.scanOrigin(ts.URL)

	if gotMethod != "GET" {
		t.Errorf("expected GET fallback, got %s", gotMethod)
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"nginx/1.24.0", "1.24.0"},
		{"PHP/8.2.10", "8.2.10"},
		{"Apache/2.4.57 (Ubuntu)", "2.4.57"},
		{"Server", ""},
		{"1.0", "1.0"},
	}
	for _, tt := range tests {
		got := extractVersion(tt.input)
		if got != tt.want {
			t.Errorf("extractVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractMetaGenerator(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{`<meta name="generator" content="WordPress 6.4">`, "WordPress 6.4"},
		{`<meta content="Drupal 10" name="generator">`, "Drupal 10"},
		{`<html><head></head></html>`, ""},
		{`<meta name="description" content="foo">`, ""},
	}
	for _, tt := range tests {
		got := extractMetaGenerator(tt.input)
		if got != tt.want {
			t.Errorf("extractMetaGenerator(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestTechFingerprintWeb_CSRFToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><meta name="csrf-token" content="abc123"></body></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "laravel" {
			found = true
		}
	}
	if !found {
		t.Error("Laravel not detected from csrf-token")
	}
}

func TestTechFingerprintWeb_EmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 results from empty response, got %d", len(results))
	}
}

func TestTechFingerprintWeb_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 results from 500, got %d", len(results))
	}
}

func TestTechFingerprintWeb_Shopify(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "shopify_track=abc")
		fmt.Fprint(w, `<html><script src="https://cdn.shopify.com/s/files/1/script.js"></script></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "shopify" {
			found = true
		}
	}
	if !found {
		t.Error("Shopify not detected")
	}
}

func TestTechFingerprintWeb_JQuery(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><script src="/js/jquery-3.7.1.min.js"></script></html>`)
	}))
	defer ts.Close()

	d := NewTechFingerprintWeb(ts.Client())
	results := d.scanOrigin(ts.URL)

	found := false
	for _, r := range results {
		if r.Technology == "jquery" {
			found = true
			if r.Version != "3.7.1" {
				t.Errorf("expected jQuery version 3.7.1, got %q", r.Version)
			}
		}
	}
	if !found {
		t.Error("jQuery not detected")
	}
}
```

- [ ] **Step 5: Run tests and verify**

Run: `go test -v -race ./internal/recon/ -run TestTechFingerprintWeb`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add internal/recon/detector_techweb.go internal/recon/detector_techweb_test.go
git commit -m "feat(recon): add TechFingerprintWeb detector with confidence scoring"
```

---

### Task 2: Source Fingerprinting Detector

**Files:**
- Create: `internal/scanner/techsource.go`
- Create: `internal/scanner/techsource_test.go`

- [ ] **Step 1: Create source fingerprinting module**

Create `internal/scanner/techsource.go`:

```go
package scanner

import (
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

// techSignal represents a single source-code detection signal.
type techSignal struct {
	Technology string
	Category   string // cms, framework, library
	Severity   finding.Severity
}

// DetectSourceTech detects technologies from file content based on file name and content patterns.
func DetectSourceTech(content, path string) []finding.Finding {
	var findings []finding.Finding
	seen := make(map[string]bool)

	base := filepath.Base(path)
	lower := strings.ToLower(content)

	// Package manifest detection
	detectPackageManifest(base, lower, &findings, seen)
	// Config file detection
	detectConfigFile(base, &findings, seen)
	// Import pattern detection (JS/TS only)
	if isJSType(base) {
		detectImports(lower, &findings, seen)
	}

	return findings
}

func detectPackageManifest(base, lower string, findings *[]finding.Finding, seen map[string]bool) {
	type manifestRule struct {
		Package string
		Tech    techSignal
	}
	rules := []manifestRule{}

	switch base {
	case "package.json":
		rules = []manifestRule{
			{"\"next\":", techSignal{"nextjs", "framework", finding.SeverityMedium}},
			{"\"nuxt\":", techSignal{"nuxtjs", "framework", finding.SeverityMedium}},
			{"\"gatsby\":", techSignal{"gatsby", "framework", finding.SeverityMedium}},
			{"\"express\":", techSignal{"express", "framework", finding.SeverityMedium}},
			{"\"react\":", techSignal{"react", "library", finding.SeverityLow}},
			{"\"vue\":", techSignal{"vue", "library", finding.SeverityLow}},
			{"\"@angular/core\":", techSignal{"angular", "library", finding.SeverityLow}},
		}
	case "composer.json":
		rules = []manifestRule{
			{"\"laravel/framework\":", techSignal{"laravel", "framework", finding.SeverityMedium}},
			{"\"symfony/\":", techSignal{"symfony", "framework", finding.SeverityMedium}},
		}
	case "Gemfile":
		rules = []manifestRule{
			{"gem 'rails'", techSignal{"rails", "framework", finding.SeverityMedium}},
			{"gem \"rails\"", techSignal{"rails", "framework", finding.SeverityMedium}},
		}
	case "requirements.txt":
		rules = []manifestRule{
			{"django", techSignal{"django", "framework", finding.SeverityMedium}},
			{"flask", techSignal{"flask", "framework", finding.SeverityMedium}},
		}
	case "go.mod":
		rules = []manifestRule{
			{"gin-gonic/gin", techSignal{"gin", "framework", finding.SeverityMedium}},
			{"gorilla/mux", techSignal{"gorilla", "framework", finding.SeverityMedium}},
		}
	case "Cargo.toml":
		rules = []manifestRule{
			{"actix-web", techSignal{"actix", "framework", finding.SeverityMedium}},
			{"axum", techSignal{"axum", "framework", finding.SeverityMedium}},
		}
	case "pom.xml":
		rules = []manifestRule{
			{"spring-boot", techSignal{"spring_boot", "framework", finding.SeverityMedium}},
		}
	case "build.gradle":
		rules = []manifestRule{
			{"spring-boot", techSignal{"spring_boot", "framework", finding.SeverityMedium}},
		}
	}

	for _, r := range rules {
		if strings.Contains(lower, r.Package) {
			addSourceFinding(findings, seen, r.Tech, "", "")
		}
	}
}

func detectConfigFile(base string, findings *[]finding.Finding, seen map[string]bool) {
	configMap := map[string]techSignal{
		"next.config.js":    {"nextjs", "framework", finding.SeverityMedium},
		"next.config.mjs":   {"nextjs", "framework", finding.SeverityMedium},
		"next.config.ts":    {"nextjs", "framework", finding.SeverityMedium},
		"nuxt.config.js":    {"nuxtjs", "framework", finding.SeverityMedium},
		"nuxt.config.ts":    {"nuxtjs", "framework", finding.SeverityMedium},
		"gatsby-config.js":  {"gatsby", "framework", finding.SeverityMedium},
		"wp-config.php":     {"wordpress", "cms", finding.SeverityHigh},
		"django-settings.py": {"django", "framework", finding.SeverityMedium},
	}
	// Check both exact match and path-contains for django settings
	if strings.Contains(base, "settings.py") && strings.Contains(base, "django") {
		addSourceFinding(findings, seen, techSignal{"django", "framework", finding.SeverityMedium}, "", "")
		return
	}
	if sig, ok := configMap[base]; ok {
		addSourceFinding(findings, seen, sig, "", "")
	}
}

func detectImports(lower string, findings *[]finding.Finding, seen map[string]bool) {
	type importRule struct {
		Pattern string
		Tech    techSignal
	}
	rules := []importRule{
		{"from 'react'", techSignal{"react", "library", finding.SeverityLow}},
		{"require('react')", techSignal{"react", "library", finding.SeverityLow}},
		{"from 'vue'", techSignal{"vue", "library", finding.SeverityLow}},
		{"from '@angular'", techSignal{"angular", "library", finding.SeverityLow}},
		{"@Component", techSignal{"angular", "library", finding.SeverityLow}},
		{"from 'express'", techSignal{"express", "framework", finding.SeverityMedium}},
		{"from 'next/", techSignal{"nextjs", "framework", finding.SeverityMedium}},
		{"import flask", techSignal{"flask", "framework", finding.SeverityMedium}},
		{"from django", techSignal{"django", "framework", finding.SeverityMedium}},
	}

	for _, r := range rules {
		if strings.Contains(lower, r.Pattern) {
			addSourceFinding(findings, seen, r.Tech, "", "")
		}
	}
}

func addSourceFinding(findings *[]finding.Finding, seen map[string]bool, tech techSignal, file, context string) {
	key := tech.Technology
	if seen[key] {
		return
	}
	seen[key] = true
	ctx := tech.Category + ": " + tech.Technology
	if context != "" {
		ctx = context
	}
	*findings = append(*findings, finding.Finding{
		File:           file,
		Line:           1,
		RuleName:       "tech_source_" + tech.Technology,
		Severity:       tech.Severity,
		ConfidenceBand: "HIGH",
		Context:        ctx,
		Secret:         tech.Technology,
	})
}

func isJSType(base string) bool {
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs":
		return true
	}
	return false
}
```

- [ ] **Step 2: Write tests**

Create `internal/scanner/techsource_test.go`:

```go
package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestDetectSourceTech_PackageJson_NextJS(t *testing.T) {
	content := `{"dependencies": {"next": "14.0.0", "react": "18.2.0"}}`
	findings := DetectSourceTech(content, "package.json")

	techs := map[string]bool{}
	for _, f := range findings {
		techs[f.Secret] = true
	}
	if !techs["nextjs"] {
		t.Error("Next.js not detected in package.json")
	}
	if !techs["react"] {
		t.Error("React not detected in package.json")
	}
}

func TestDetectSourceTech_PackageJson_Express(t *testing.T) {
	content := `{"dependencies": {"express": "^4.18.0"}}`
	findings := DetectSourceTech(content, "package.json")

	found := false
	for _, f := range findings {
		if f.Secret == "express" {
			found = true
		}
	}
	if !found {
		t.Error("Express not detected in package.json")
	}
}

func TestDetectSourceTech_ComposerJson_Laravel(t *testing.T) {
	content := `{"require": {"laravel/framework": "^10.0"}}`
	findings := DetectSourceTech(content, "composer.json")

	found := false
	for _, f := range findings {
		if f.Secret == "laravel" {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Errorf("expected MEDIUM severity, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("Laravel not detected in composer.json")
	}
}

func TestDetectSourceTech_Gemfile_Rails(t *testing.T) {
	content := `gem 'rails', '~> 7.0'`
	findings := DetectSourceTech(content, "Gemfile")

	found := false
	for _, f := range findings {
		if f.Secret == "rails" {
			found = true
		}
	}
	if !found {
		t.Error("Rails not detected in Gemfile")
	}
}

func TestDetectSourceTech_Requirements_Django(t *testing.T) {
	content := `Django==4.2
requests==2.31.0
psycopg2==2.9.7`
	findings := DetectSourceTech(content, "requirements.txt")

	found := false
	for _, f := range findings {
		if f.Secret == "django" {
			found = true
		}
	}
	if !found {
		t.Error("Django not detected in requirements.txt")
	}
}

func TestDetectSourceTech_GoMod_Gin(t *testing.T) {
	content := `require github.com/gin-gonic/gin v1.9.1`
	findings := DetectSourceTech(content, "go.mod")

	found := false
	for _, f := range findings {
		if f.Secret == "gin" {
			found = true
		}
	}
	if !found {
		t.Error("Gin not detected in go.mod")
	}
}

func TestDetectSourceTech_ConfigFile_NextConfig(t *testing.T) {
	content := `module.exports = { reactStrictMode: true }`
	findings := DetectSourceTech(content, "next.config.js")

	found := false
	for _, f := range findings {
		if f.Secret == "nextjs" {
			found = true
		}
	}
	if !found {
		t.Error("Next.js not detected from next.config.js")
	}
}

func TestDetectSourceTech_ConfigFile_WpConfig(t *testing.T) {
	content := `<?php define('DB_NAME', 'wordpress'); ?>`
	findings := DetectSourceTech(content, "wp-config.php")

	found := false
	for _, f := range findings {
		if f.Secret == "wordpress" {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("expected HIGH severity for WordPress, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("WordPress not detected from wp-config.php")
	}
}

func TestDetectSourceTech_Imports_React(t *testing.T) {
	content := `import React from 'react'; import { useState } from 'react';`
	findings := DetectSourceTech(content, "app.jsx")

	found := false
	for _, f := range findings {
		if f.Secret == "react" {
			found = true
		}
	}
	if !found {
		t.Error("React not detected from import patterns")
	}
}

func TestDetectSourceTech_Imports_Vue(t *testing.T) {
	content := `import { ref } from 'vue'`
	findings := DetectSourceTech(content, "component.vue")

	found := false
	for _, f := range findings {
		if f.Secret == "vue" {
			found = true
		}
	}
	if !found {
		t.Error("Vue not detected from import patterns")
	}
}

func TestDetectSourceTech_Imports_Express(t *testing.T) {
	content := `const express = require('express'); import express from 'express';`
	findings := DetectSourceTech(content, "server.js")

	found := false
	for _, f := range findings {
		if f.Secret == "express" {
			found = true
		}
	}
	if !found {
		t.Error("Express not detected from import patterns")
	}
}

func TestDetectSourceTech_NoFalsePositive(t *testing.T) {
	content := `This is a plain text file with no technology signals.`
	findings := DetectSourceTech(content, "readme.txt")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings from plain text, got %d", len(findings))
	}
}

func TestDetectSourceTech_UnrelatedFile(t *testing.T) {
	content := `{"name": "my-app"}`
	findings := DetectSourceTech(content, "unknown.xyz")

	if len(findings) != 0 {
		t.Errorf("expected 0 findings from unknown file, got %d", len(findings))
	}
}

func TestDetectSourceTech_CargoToml_Actix(t *testing.T) {
	content := `[dependencies]
actix-web = "4"
serde = { version = "1", features = ["derive"] }`
	findings := DetectSourceTech(content, "Cargo.toml")

	found := false
	for _, f := range findings {
		if f.Secret == "actix" {
			found = true
		}
	}
	if !found {
		t.Error("Actix not detected in Cargo.toml")
	}
}

func TestDetectSourceTech_Dedup(t *testing.T) {
	content := `{"dependencies": {"next": "14.0.0"}, "devDependencies": {"next": "14.0.0"}}`
	findings := DetectSourceTech(content, "package.json")

	count := 0
	for _, f := range findings {
		if f.Secret == "nextjs" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 Next.js finding, got %d", count)
	}
}
```

- [ ] **Step 3: Run tests and verify**

Run: `go test -v -race ./internal/scanner/ -run TestDetectSourceTech`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/techsource.go internal/scanner/techsource_test.go
git commit -m "feat(scanner): add source code technology fingerprinting"
```

---

### Task 3: Scanner Config + CLI Flag

**Files:**
- Modify: `internal/scanner/scanner.go`
- Modify: `cmd/scan.go`

- [ ] **Step 1: Add TechDetect to Config**

In `internal/scanner/scanner.go`, add `TechDetect bool` to the Config struct after `HeaderCheck`:

```go
	HeaderCheck   bool                // analyze HTTP security headers on discovered URLs
	TechDetect    bool                // detect technologies from HTTP responses and source code
```

- [ ] **Step 2: Add --tech-detect flag in cmd/scan.go**

Add the flag variable at line 117 (after `headerCheck`):

```go
	headerCheck       bool
	techDetect        bool
```

Add flag registration in `init()` after the `--header-check` line:

```go
	scanCmd.Flags().BoolVar(&techDetect, "tech-detect", true, "detect technologies from HTTP responses and source code (use --no-tech-detect to disable)")
```

Add to `scanCfg` struct after `HeaderCheck`:

```go
		HeaderCheck:       headerCheck,
		TechDetect:        techDetect,
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/scanner.go cmd/scan.go
git commit -m "feat: add --tech-detect flag and scanner config"
```

---

### Task 4: Wire Web Detector into ScanURLs + CollectorStage

**Files:**
- Modify: `internal/scanner/scan.go`
- Modify: `internal/scanner/stage_collector.go`

- [ ] **Step 1: Register web detector in stage_collector.go**

In `NewCollectorStage()`, after the `if cfg.HeaderCheck` block, add:

```go
	if cfg.TechDetect {
		httpCl := httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)
		s.reconReg.Register(recon.NewTechFingerprintWeb(httpCl))
	}
```

- [ ] **Step 2: Wire web detector into ScanURLs**

In `internal/scanner/scan.go`, after the security header analysis block (around line 1078), add:

```go
	// Technology fingerprinting on crawled URLs
	if cfg.TechDetect && len(crawled) > 0 {
		techDetector := recon.NewTechFingerprintWeb(httpClient)
		crawledURLs := make([]string, 0, len(crawled))
		for _, c := range crawled {
			crawledURLs = append(crawledURLs, c.URL)
		}
		for _, sf := range techDetector.Detect(crawledURLs) {
			allFindings = append(allFindings, finding.Finding{
				File:           sf.URL,
				Line:           1,
				RuleName:       sf.Source,
				Severity:       sf.Severity,
				ConfidenceBand: confidenceBandFromScore(sf.Confidence),
				Context:        fmt.Sprintf("%s: %s (confidence=%d)", sf.Category, sf.URL, sf.Confidence),
				Confidence:     sf.Confidence,
			})
		}
	}
```

- [ ] **Step 3: Add confidenceBandFromScore helper**

In `internal/scanner/scan.go`, add near the bottom (before `FilterNewOnly`):

```go
func confidenceBandFromScore(score int) string {
	switch {
	case score >= 95:
		return "CRITICAL"
	case score >= 80:
		return "HIGH"
	case score >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
```

- [ ] **Step 4: Verify build**

Run: `go build ./...`
Expected: Build succeeds

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scan.go internal/scanner/stage_collector.go
git commit -m "feat: wire TechFingerprintWeb into ScanURLs and CollectorStage"
```

---

### Task 5: Wire Source Detector into scanContent

**Files:**
- Modify: `internal/scanner/scan.go`

- [ ] **Step 1: Add source fingerprinting call in scanContent**

At the end of `scanContent()` (before `return findings`, around line 796), add:

```go
	// Source technology fingerprinting
	if cfg.TechDetect {
		findings = append(findings, DetectSourceTech(content, path)...)
	}
```

- [ ] **Step 2: Verify build and run tests**

Run: `go build ./... && go test -race ./...`
Expected: Build succeeds, all tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/scan.go
git commit -m "feat: wire source technology detection into scanContent"
```

---

### Task 6: Full Verification + Integration Test

**Files:**
- Create (temp): integration test using httptest

- [ ] **Step 1: Write integration test**

Add to `internal/recon/detector_techweb_test.go`:

```go
func TestTechFingerprintWeb_MultipleServers(t *testing.T) {
	// WordPress server
	wpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2")
		w.Header().Set("Server", "Apache/2.4.57")
		fmt.Fprint(w, `<html><head><meta name="generator" content="WordPress 6.4"></head><body></body></html>`)
	}))
	defer wpServer.Close()

	// Express server
	expressServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Set-Cookie", "connect.sid=s%3Abigsecret")
		fmt.Fprint(w, `<html><body><script>window.__NEXT_DATA__={}</script></body></html>`)
	}))
	defer expressServer.Close()

	// Bare Nginx server
	nginxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		fmt.Fprint(w, `<html><body>Hello</body></html>`)
	}))
	defer nginxServer.Close()

	d := NewTechFingerprintWeb(httptest.DefaultClient)
	findings := d.Detect([]string{wpServer.URL, expressServer.URL, nginxServer.URL})

	techs := make(map[string]bool)
	for _, f := range findings {
		techs[f.Category+":"+f.Source] = true
	}

	// WordPress server should be detected
	if !techs["cms:tech_cms_wordpress"] {
		t.Error("WordPress not detected")
	}
	if !techs["language:tech_language_php"] {
		t.Error("PHP not detected")
	}

	// Express server should be detected
	if !techs["framework:tech_framework_express"] {
		t.Error("Express not detected")
	}

	// Nginx should be detected
	if !techs["server:tech_server_nginx"] {
		t.Error("Nginx not detected")
	}
}
```

- [ ] **Step 2: Run all tests**

Run: `go test -v -race ./...`
Expected: All packages pass

- [ ] **Step 3: Run vet and format checks**

Run: `go vet ./... && gofmt -l .`
Expected: Clean output

- [ ] **Step 4: Build and smoke test**

Run: `go build -o /tmp/syck_tech . && /tmp/syck_tech --help`
Expected: `--tech-detect` flag visible, default true

- [ ] **Step 5: Smoke test with URL scan**

Run: `/tmp/syck_tech scan -u https://example.com --no-color --tech-detect 2>&1 | head -20`
Expected: Tech findings or empty (depending on example.com response)

- [ ] **Step 6: Commit integration test**

```bash
git add internal/recon/detector_techweb_test.go
git commit -m "test(recon): add multi-server integration test for tech fingerprinting"
```
