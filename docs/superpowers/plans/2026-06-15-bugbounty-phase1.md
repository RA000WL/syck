# Bug Bounty Core V1.5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 10 bug bounty features to SYCK: shared HTTP client factory, proxy/auth/cookie/scope-file flags, robots/sitemap discovery, cloud metadata + .env rules, diff mode, JSONL output, and configurable HTTP timeouts.

**Architecture:** New `internal/httpclient` package provides a shared transport/client factory used by scanner, crawler, validator, and formatters. Sitemap discovery extends the existing `RobotsCache` with a new `SitemapFetcher`. All 8 new CLI flags are wired through `scanner.Config` into the existing scan pipeline.

**Tech Stack:** Go 1.26, `net/http`, `encoding/xml`, `regexp`, cobra/viper, `net/http/cookiejar`

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `internal/httpclient/client.go` | CREATE | Shared HTTP transport + client factory |
| `internal/httpclient/client_test.go` | CREATE | Factory tests |
| `internal/crawler/sitemap.go` | CREATE | Sitemap XML parsing + fetching |
| `internal/crawler/sitemap_test.go` | CREATE | Sitemap parsing tests |
| `internal/formatters/jsonl.go` | CREATE | JSONL output formatter |
| `internal/formatters/jsonl_test.go` | CREATE | JSONL formatter tests |
| `internal/scanner/scanner.go` | MODIFY | Add Config fields |
| `internal/scanner/scan.go` | MODIFY | Diff filter, client factory usage |
| `internal/crawler/robots.go` | MODIFY | Parse Sitemap: directives |
| `internal/crawler/crawler.go` | MODIFY | Integrate sitemap discovery |
| `internal/crawler/juicy.go` | MODIFY | Use injected client |
| `internal/formatters/formatter.go` | MODIFY | Register jsonl |
| `internal/formatters/webhook.go` | MODIFY | Accept proxyURL |
| `internal/validator/http.go` | MODIFY | Use shared transport |
| `internal/rules/builtin.yaml` | MODIFY | +9 new rules |
| `cmd/scan.go` | MODIFY | Add 8 flags, scope parsing, diff, cookie |
| `cmd/env.go` | MODIFY | No changes needed (auto-binds) |
| `cmd/upload_sarif.go` | MODIFY | Accept proxyURL |

---

## Task 1: HTTP Client Factory

**Files:**
- Create: `internal/httpclient/client.go`
- Create: `internal/httpclient/client_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/httpclient/client_test.go`:

```go
package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestNewTransport_Default(t *testing.T) {
	tr := NewTransport("", false)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Proxy != nil {
		t.Error("expected nil Proxy when proxyURL is empty (should use ProxyFromEnvironment)")
	}
}

func TestNewTransport_WithProxy(t *testing.T) {
	tr := NewTransport("http://127.0.0.1:8080", false)
	if tr == nil {
		t.Fatal("expected non-nil transport")
	}
	if tr.Proxy == nil {
		t.Fatal("expected non-nil Proxy function")
	}
}

func TestNewTransport_InsecureSkipVerify(t *testing.T) {
	tr := NewTransport("", true)
	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

func TestNewClient_Timeout(t *testing.T) {
	c := NewClient(15*time.Second, "", false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Timeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", c.Timeout)
	}
}

func TestNewClient_RedirectPolicy(t *testing.T) {
	c := NewClient(10*time.Second, "", false)
	if c.CheckRedirect == nil {
		t.Fatal("expected non-nil CheckRedirect")
	}
}

func TestNewClient_ProxyPassthrough(t *testing.T) {
	c := NewClient(10*time.Second, "http://127.0.0.1:8080", false)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	transport, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}
	if transport.Proxy == nil {
		t.Error("expected non-nil Proxy on transport")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/httpclient/ -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement the factory**

Create `internal/httpclient/client.go`:

```go
// Package httpclient provides a shared HTTP client factory for all syck components.
package httpclient

import (
	"net/http"
	"net/url"
	"time"
)

// NewTransport creates an http.Transport with optional proxy and TLS settings.
// If proxyURL is empty, falls back to http.ProxyFromEnvironment (respects HTTP_PROXY env vars).
func NewTransport(proxyURL string, insecureSkipVerify bool) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- validator needs this
	}
	return tr
}

// NewClient creates an http.Client with the given timeout, proxy, and TLS settings.
func NewClient(timeout time.Duration, proxyURL string, insecureSkipVerify bool) *http.Client {
	transport := NewTransport(proxyURL, insecureSkipVerify)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}
```

Wait — the imports are missing. Let me fix:

```go
package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func NewTransport(proxyURL string, insecureSkipVerify bool) *http.Transport {
	tr := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- validator needs this
	}
	return tr
}

func NewClient(timeout time.Duration, proxyURL string, insecureSkipVerify bool) *http.Client {
	transport := NewTransport(proxyURL, insecureSkipVerify)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/httpclient/ -v -race`
Expected: ALL PASS

- [ ] **Step 5: Run vet and format**

Run: `go vet ./internal/httpclient/` and `gofmt -l internal/httpclient/`
Expected: clean

- [ ] **Step 6: Commit**

```bash
git add internal/httpclient/client.go internal/httpclient/client_test.go
git commit -m "feat(httpclient): add shared HTTP transport and client factory"
```

---

## Task 2: Scanner Config Extensions + Header Transport

**Files:**
- Modify: `internal/scanner/scanner.go`
- Create: `internal/scanner/header_transport.go`
- Create: `internal/scanner/header_transport_test.go`

- [ ] **Step 1: Write failing test for header transport**

Create `internal/scanner/header_transport_test.go`:

```go
package scanner

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeaderTransport_CloneAndInject(t *testing.T) {
	var gotHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer ts.Close()

	transport := &headerTransport{
		base: http.DefaultTransport,
		headers: map[string][]string{
			"Authorization": {"Bearer test-token"},
			"Cookie":        {"a=1", "b=2"},
			"X-Custom":      {"val1"},
		},
	}
	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Original", "yes")
	client.Do(req)

	if gotHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf("Authorization header: got %q", gotHeaders.Get("Authorization"))
	}
	cookies := gotHeaders.Values("Cookie")
	if len(cookies) != 2 || cookies[0] != "a=1" || cookies[1] != "b=2" {
		t.Errorf("Cookie headers: got %v", cookies)
	}
	if gotHeaders.Get("Original") != "yes" {
		t.Error("original header should be preserved")
	}
}

func TestHeaderTransport_CloneDoesNotMutateOriginal(t *testing.T) {
	transport := &headerTransport{
		base:    http.DefaultTransport,
		headers: map[string][]string{"X-Injected": {"yes"}},
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Original", "yes")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Injected") != "yes" {
			t.Error("expected injected header on server side")
		}
		if r.Header.Get("X-Original") != "yes" {
			t.Error("expected original header preserved")
		}
	}))
	defer ts.Close()

	client := &http.Client{Transport: transport}
	req.URL, _ = req.URL.Parse(ts.URL)
	client.Do(req)

	// Verify original request was NOT mutated
	if req.Header.Get("X-Injected") != "" {
		t.Error("original request was mutated — clone failed")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestHeaderTransport -v`
Expected: FAIL — `headerTransport` type not defined

- [ ] **Step 3: Add Config fields and header transport**

Add to `internal/scanner/scanner.go` (after existing Config fields):

```go
type Config struct {
	// ... existing fields ...

	// Phase 1: Bug bounty core
	HTTPTimeout  time.Duration           // HTTP client timeout for all requests (default 10s)
	ProxyURL     string                  // HTTP proxy URL for all requests
	Headers      map[string][]string     // custom headers to inject into crawl requests
	ScopePatterns []*regexp.Regexp       // compiled scope patterns from --scope-file
	Diff         bool                    // only output new findings (requires CacheDB)
	CookieString string                  // cookie string to inject (name=value; name2=value2)
	NoSitemap    bool                    // disable robots/sitemap discovery
}
```

Add `"time"` to the imports if not already present.

Create `internal/scanner/header_transport.go`:

```go
package scanner

import "net/http"

// headerTransport injects custom headers into all HTTP requests.
// It clones each request before modification to avoid mutating the original.
type headerTransport struct {
	base    http.RoundTripper
	headers map[string][]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	for k, vals := range t.headers {
		for _, v := range vals {
			cloned.Header.Add(k, v)
		}
	}
	return t.base.RoundTrip(cloned)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/scanner/ -run TestHeaderTransport -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/header_transport.go internal/scanner/header_transport_test.go
git commit -m "feat(scanner): add Config extensions and header transport"
```

---

## Task 3: CLI Flags — Proxy, Auth, Scope-File, Cookie, Diff, Timeout, Sitemap

**Files:**
- Modify: `cmd/scan.go`
- Modify: `internal/scanner/scan.go` (diff validation)

- [ ] **Step 1: Add flag vars and registration**

Add these vars to the `var` block in `cmd/scan.go` (after `adaptiveFlag`):

```go
proxyURL         string
authToken        string
headerList       []string
scopeFile        string
cookieString     string
noSitemap        bool
diffMode         bool
httpTimeout      string
```

Add these flag registrations to `init()` (after the existing flags):

```go
scanCmd.Flags().StringVar(&proxyURL, "proxy", "", "HTTP proxy URL for all requests (e.g. http://127.0.0.1:8080)")
scanCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for authenticated crawl requests")
scanCmd.Flags().StringArrayVar(&headerList, "header", nil, "custom header in 'Name: Value' format (can be repeated)")
scanCmd.Flags().StringVar(&scopeFile, "scope-file", "", "file with scope regex patterns (one per line, # comments)")
scanCmd.Flags().StringVar(&cookieString, "cookie", "", "cookie string in 'name=value; name2=value2' format")
scanCmd.Flags().BoolVar(&noSitemap, "no-sitemap", false, "disable robots.txt/sitemap.xml discovery")
scanCmd.Flags().BoolVar(&diffMode, "diff", false, "only show new findings (requires --cache-db)")
scanCmd.Flags().StringVar(&httpTimeout, "http-timeout", "10s", "HTTP client timeout (e.g. 10s, 30s)")
```

- [ ] **Step 2: Add scope-file parsing in runScan**

In `cmd/scan.go`, after the scope regex compilation block (search for `scopeStr`), add:

```go
// Parse --scope-file patterns
var scopePatterns []*regexp.Regexp
if scopeFile != "" {
	f, err := os.Open(scopeFile)
	if err != nil {
		return fmt.Errorf("open scope file: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			return fmt.Errorf("invalid scope pattern %q: %w", line, err)
		}
		scopePatterns = append(scopePatterns, re)
	}
	if len(scopePatterns) == 0 {
		return fmt.Errorf("scope file %q contains no valid patterns", scopeFile)
	}
}
```

- [ ] **Step 3: Add header parsing (auth-token + header flags)**

In `cmd/scan.go`, after the scope parsing block, add:

```go
// Parse headers from --auth-token and --header flags
headers := make(map[string][]string)
if authToken != "" {
	headers["Authorization"] = append(headers["Authorization"], "Bearer "+authToken)
}
for _, h := range headerList {
	parts := strings.SplitN(h, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid --header format %q: expected 'Name: Value'", h)
	}
	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if name == "" || value == "" {
		return fmt.Errorf("invalid --header format %q: name and value required", h)
	}
	headers[name] = append(headers[name], value)
}
```

- [ ] **Step 4: Add diff validation**

In `cmd/scan.go`, after the headers block, add:

```go
// Validate --diff requires --cache-db
if diffMode && cacheDB == "" {
	return fmt.Errorf("--diff requires --cache-db for cross-run comparison")
}
```

- [ ] **Step 5: Add timeout parsing**

In `cmd/scan.go`, after the diff validation, add:

```go
// Parse --http-timeout
parsedTimeout, err := time.ParseDuration(httpTimeout)
if err != nil {
	return fmt.Errorf("invalid --http-timeout: %w", err)
}
if parsedTimeout < time.Second {
	parsedTimeout = time.Second
}
```

Add `"time"` to the imports of `cmd/scan.go`.

- [ ] **Step 6: Wire new fields into scanner.Config**

In `cmd/scan.go`, find the `scanCfg := scanner.Config{...}` block and add the new fields:

```go
scanCfg := scanner.Config{
	// ... existing fields ...
	HTTPTimeout:    parsedTimeout,
	ProxyURL:       proxyURL,
	Headers:        headers,
	ScopePatterns:  scopePatterns,
	Diff:           diffMode,
	CookieString:   cookieString,
	NoSitemap:      noSitemap,
}
```

- [ ] **Step 7: Run build**

Run: `go build ./...`
Expected: PASS (may need to add imports)

- [ ] **Step 8: Commit**

```bash
git add cmd/scan.go
git commit -m "feat(cli): add 8 new bug bounty flags (proxy, auth, scope-file, cookie, sitemap, diff, timeout)"
```

---

## Task 4: Client Factory Wiring — Update All Call Sites

**Files:**
- Modify: `internal/scanner/scan.go` (ScanURLs client)
- Modify: `internal/crawler/juicy.go` (juicy client)
- Modify: `internal/crawler/robots.go` (default client)
- Modify: `internal/formatters/webhook.go` (webhook client)
- Modify: `internal/validator/http.go` (validator client)
- Modify: `cmd/upload_sarif.go` (SARIF upload client)

- [ ] **Step 1: Update ScanURLs in scan.go**

In `internal/scanner/scan.go`, replace the inline `httpClient` creation at line ~879:

```go
// BEFORE:
httpClient := &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        if len(via) >= 5 {
            return fmt.Errorf("too many redirects")
        }
        return nil
    },
}

// AFTER:
httpClient := httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)
```

Add `"github.com/RA000WL/syck/internal/httpclient"` to imports.

- [ ] **Step 2: Update ProbeJuicy in juicy.go**

In `internal/crawler/juicy.go`, replace the nil check fallback at line ~61:

```go
// BEFORE:
if cfg.Client == nil {
    cfg.Client = &http.Client{Timeout: 10 * time.Second}
}

// AFTER:
if cfg.Client == nil {
    cfg.Client = httpclient.NewClient(10*time.Second, "", false)
}
```

Add `"github.com/RA000WL/syck/internal/httpclient"` to imports. Remove `"time"` from imports only if it's still used elsewhere (it is, for `maxJuicyBodyBytes` etc).

- [ ] **Step 3: Update defaultHTTPClient in robots.go**

In `internal/crawler/robots.go`, replace the `NewRobotsCache` fallback client creation. Currently `defaultHTTPClient` is referenced but defined in `crawler.go`. Update `NewRobotsCache`:

```go
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
```

Remove the reference to `defaultHTTPClient` from `robots.go`. Add `"github.com/RA000WL/syck/internal/httpclient"` to imports.

- [ ] **Step 4: Update webhook.go**

In `internal/formatters/webhook.go`, change `PostWebhook` to accept proxyURL:

```go
func PostWebhook(url string, style WebhookStyle, findings []finding.Finding, opts ...WebhookOption) error {
```

Add a `WebhookOption` type and functional options pattern:

```go
type WebhookOption func(*webhookConfig)

type webhookConfig struct {
	proxyURL string
}

func WithProxy(url string) WebhookOption {
	return func(c *webhookConfig) { c.proxyURL = url }
}
```

Then in the function body:

```go
func PostWebhook(url string, style WebhookStyle, findings []finding.Finding, opts ...WebhookOption) error {
	var cfg webhookConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	// ... existing URL check, body marshaling ...

	client := httpclient.NewClient(10*time.Second, cfg.proxyURL, false)
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	// ... rest unchanged ...
}
```

Add `"github.com/RA000WL/syck/internal/httpclient"` to imports.

- [ ] **Step 5: Update validator/http.go**

In `internal/validator/http.go`, replace the package-level `httpClient`:

```go
var (
	httpClient       *http.Client
	defaultRateLimiter = NewRateLimiter(5.0)
)

// InitValidatorClient sets the validator's HTTP client with proxy support.
// Called from scan.go after flags are parsed.
func InitValidatorClient(proxyURL string) {
	httpClient = httpclient.NewClient(5*time.Second, proxyURL, true)
}

func init() {
	// Default client without proxy (for standalone validator usage)
	httpClient = httpclient.NewClient(5*time.Second, "", true)
}
```

Add `"github.com/RA000WL/syck/internal/httpclient"` to imports. Remove `"crypto/tls"` and `"time"` if no longer needed.

- [ ] **Step 6: Update upload_sarif.go**

In `cmd/upload_sarif.go`, replace the client creation at line ~82:

```go
// BEFORE:
client := &http.Client{Timeout: 30 * time.Second}

// AFTER:
client := httpclient.NewClient(30*time.Second, proxyURL, false)
```

Add `"github.com/RA000WL/syck/internal/httpclient"` to imports. Remove `"time"` only if not used elsewhere.

- [ ] **Step 7: Run all tests**

Run: `go test -race ./...`
Expected: ALL PASS

- [ ] **Step 8: Run vet and format**

Run: `go vet ./...` and `gofmt -l .`
Expected: clean

- [ ] **Step 9: Commit**

```bash
git add internal/scanner/scan.go internal/crawler/juicy.go internal/crawler/robots.go internal/formatters/webhook.go internal/validator/http.go cmd/upload_sarif.go
git commit -m "feat(httpclient): wire shared client factory into all 6 call sites"
```

---

## Task 5: Sitemap Discovery

**Files:**
- Create: `internal/crawler/sitemap.go`
- Create: `internal/crawler/sitemap_test.go`
- Modify: `internal/crawler/robots.go`
- Modify: `internal/crawler/crawler.go`

- [ ] **Step 1: Write failing tests for robots.txt Sitemap parsing**

Add to `internal/crawler/robots_test.go` (or create if missing):

```go
func TestParseRobotsTxt_Sitemaps(t *testing.T) {
	content := `User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap_index.xml

User-agent: Googlebot
Allow: /
`
	rule := parseRobotsTxt(content)
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if len(rule.sitemaps) != 2 {
		t.Fatalf("expected 2 sitemaps, got %d", len(rule.sitemaps))
	}
	if rule.sitemaps[0] != "https://example.com/sitemap.xml" {
		t.Errorf("unexpected sitemap[0]: %s", rule.sitemaps[0])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crawler/ -run TestParseRobotsTxt_Sitemaps -v`
Expected: FAIL — `sitemaps` field not defined on `robotsRule`

- [ ] **Step 3: Extend robotsRule and parseRobotsTxt**

In `internal/crawler/robots.go`, modify `robotsRule`:

```go
type robotsRule struct {
	entries    []robotsEntry
	sitemaps   []string
	crawlDelay time.Duration
}
```

In `parseRobotsTxt`, add a case for `sitemap`:

```go
case "sitemap":
	if value != "" {
		rule.sitemaps = append(rule.sitemaps, value)
	}
```

Also update the nil-return check at the end:

```go
// BEFORE:
if len(rule.entries) == 0 && rule.crawlDelay == 0 {
    return nil
}

// AFTER:
if len(rule.entries) == 0 && rule.sitemaps == 0 && rule.crawlDelay == 0 {
    return nil
}
```

Add `Sitemaps` method to `RobotsCache`:

```go
// Sitemaps returns sitemap URLs found in robots.txt for the given domain.
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
```

- [ ] **Step 4: Run robots tests**

Run: `go test ./internal/crawler/ -run TestParseRobotsTxt -v -race`
Expected: PASS (existing + new test)

- [ ] **Step 5: Write sitemap parsing tests**

Create `internal/crawler/sitemap_test.go`:

```go
package crawler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseSitemap(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/page1</loc>
    <lastmod>2026-01-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
  </url>
</urlset>`
	urls := ParseSitemap(xml)
	if len(urls) != 2 {
		t.Fatalf("expected 2 URLs, got %d", len(urls))
	}
	if urls[0].Loc != "https://example.com/page1" {
		t.Errorf("unexpected loc: %s", urls[0].Loc)
	}
	if urls[0].LastMod != "2026-01-01" {
		t.Errorf("unexpected lastmod: %s", urls[0].LastMod)
	}
	if urls[1].Loc != "https://example.com/page2" {
		t.Errorf("unexpected loc: %s", urls[1].Loc)
	}
}

func TestParseSitemapIndex(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>`
	sitemaps := ParseSitemapIndex(xml)
	if len(sitemaps) != 2 {
		t.Fatalf("expected 2 sitemaps, got %d", len(sitemaps))
	}
	if sitemaps[0] != "https://example.com/sitemap1.xml" {
		t.Errorf("unexpected sitemap: %s", sitemaps[0])
	}
}

func TestFetchSitemaps_RobotsDirectives(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/robots-sitemap-page</loc></url></urlset>`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	fetcher := &SitemapFetcher{client: ts.Client(), ua: "test"}
	urls := fetcher.FetchSitemaps("example.com", []string{ts.URL + "/sitemap.xml"})
	if len(urls) != 1 {
		t.Fatalf("expected 1 URL, got %d: %v", len(urls), urls)
	}
}

func TestFetchSitemaps_DeduplicatesStandardPaths(t *testing.T) {
	called := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(200)
		w.Write([]byte(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/page</loc></url></urlset>`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	fetcher := &SitemapFetcher{client: ts.Client(), ua: "test"}
	// robotsSitemaps already includes /sitemap.xml — should not fetch again
	urls := fetcher.FetchSitemaps("example.com", []string{ts.URL + "/sitemap.xml"})
	_ = urls
	if called != 0 {
		t.Errorf("expected 0 fetches (already in robots), got %d", called)
	}
}
```

- [ ] **Step 6: Implement sitemap.go**

Create `internal/crawler/sitemap.go`:

```go
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
)

type SitemapFetcher struct {
	client *http.Client
	ua     string
}

type SitemapURL struct {
	Loc        string
	LastMod    string
	ChangeFreq string
	Priority   string
}

type sitemapURLSet struct {
	URLs []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod"`
	ChangeFreq string `xml:"changefreq"`
	Priority   string `xml:"priority"`
}

type sitemapIndex struct {
	Sitemaps []sitemapIndexEntry `xml:"sitemap"`
}

type sitemapIndexEntry struct {
	Loc string `xml:"loc"`
}

type sitemapState struct {
	fetched int
	urls    int
}

func (sf *SitemapFetcher) FetchSitemaps(domain string, robotsSitemaps []string) []string {
	if sf.client == nil {
		return nil
	}

	state := &sitemapState{}
	seen := make(map[string]bool)
	var result []string

	// Process robots.txt sitemap directives
	for _, sitemapURL := range robotsSitemaps {
		if state.fetched >= MaxSitemapsPerDomain || state.urls >= MaxURLsFromSitemaps {
			break
		}
		if seen[sitemapURL] {
			continue
		}
		seen[sitemapURL] = true
		state.fetched++
		sf.fetchAndParse(sitemapURL, 0, state, seen, &result)
	}

	// Try standard paths
	for _, path := range []string{"/sitemap.xml", "/sitemap_index.xml"} {
		if state.fetched >= MaxSitemapsPerDomain || state.urls >= MaxURLsFromSitemaps {
			break
		}
		rawURL := "https://" + domain + path
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		state.fetched++
		sf.fetchAndParse(rawURL, 0, state, seen, &result)
	}

	return result
}

func (sf *SitemapFetcher) fetchAndParse(rawURL string, depth int, state *sitemapState, seen map[string]bool, result *[]string) {
	if depth > MaxSitemapDepth || state.fetched > MaxSitemapsPerDomain || state.urls >= MaxURLsFromSitemaps {
		return
	}

	resp, err := sf.get(rawURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return
	}

	content := string(body)

	if strings.Contains(content, "<sitemapindex") {
		indexURLs := ParseSitemapIndex(content)
		for _, sitemapURL := range indexURLs {
			if state.fetched >= MaxSitemapsPerDomain || state.urls >= MaxURLsFromSitemaps {
				break
			}
			if seen[sitemapURL] {
				continue
			}
			seen[sitemapURL] = true
			state.fetched++
			sf.fetchAndParse(sitemapURL, depth+1, state, seen, result)
		}
	} else {
		sitemapURLs := ParseSitemap(content)
		for _, u := range sitemapURLs {
			if state.urls >= MaxURLsFromSitemaps {
				break
			}
			if u.Loc == "" || seen[u.Loc] {
				continue
			}
			seen[u.Loc] = true
			state.urls++
			*result = append(*result, u.Loc)
		}
	}
}

func (sf *SitemapFetcher) get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	if sf.ua != "" {
		req.Header.Set("User-Agent", sf.ua)
	} else {
		req.Header.Set("User-Agent", "SyckBot/2.0 (+https://github.com/RA000WL/syck)")
	}
	req.Header.Set("Accept", "application/xml, text/xml, */*")
	return sf.client.Do(req)
}

func ParseSitemap(content string) []SitemapURL {
	var set sitemapURLSet
	if err := xml.Unmarshal([]byte(content), &set); err != nil {
		return nil
	}
	var result []SitemapURL
	for _, u := range set.URLs {
		if u.Loc != "" {
			result = append(result, SitemapURL{
				Loc:        u.Loc,
				LastMod:    u.LastMod,
				ChangeFreq: u.ChangeFreq,
				Priority:   u.Priority,
			})
		}
	}
	return result
}

func ParseSitemapIndex(content string) []string {
	var idx sitemapIndex
	if err := xml.Unmarshal([]byte(content), &idx); err != nil {
		return nil
	}
	var result []string
	for _, entry := range idx.Sitemaps {
		if entry.Loc != "" {
			result = append(result, entry.Loc)
		}
	}
	return result
}
```

Note: Fix typo `MaxSitemapPerDomain` → `MaxSitemapsPerDomain` in `fetchAndParse`.

- [ ] **Step 7: Run sitemap tests**

Run: `go test ./internal/crawler/ -run "TestParseSitemap|TestFetchSitemaps" -v -race`
Expected: PASS

- [ ] **Step 8: Integrate into crawler.go**

In `internal/crawler/crawler.go`, find where `RobotsCache.getOrCreate(domain)` is called (after BFS discovers a new domain). Add sitemap discovery:

```go
// After robots.txt processing, discover sitemaps
if cfg.SitemapEnabled && sf != nil {
    robotsSitemaps := c.robots.Sitemaps(rawURL)
    sitemapURLs := sf.FetchSitemaps(u.Hostname(), robotsSitemaps)
    for _, sURL := range sitemapURLs {
        // Scope filter BEFORE enqueue
        if c.scope != nil && !c.scope.MatchString(sURL) {
            continue
        }
        c.enqueueURL(sURL, depth+1)
    }
}
```

Add `SitemapEnabled bool` to `CrawlConfig` struct.

- [ ] **Step 9: Run all crawler tests**

Run: `go test ./internal/crawler/ -v -race`
Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add internal/crawler/sitemap.go internal/crawler/sitemap_test.go internal/crawler/robots.go internal/crawler/crawler.go
git commit -m "feat(crawler): add sitemap discovery with recursion limits and scope filtering"
```

---

## Task 6: Detection Rules — Cloud Metadata + .env

**Files:**
- Modify: `internal/rules/builtin.yaml`

- [ ] **Step 1: Add 3 cloud metadata rules**

Append to `internal/rules/builtin.yaml`:

```yaml
  # --- Cloud Metadata Endpoints ---
  - name: cloud_metadata_aws
    severity: high
    pattern: '169\.254\.169\.254(?:/latest/meta-data/|/latest/user-data/|/latest/dynamic/instance-identity/)'
    description: 'AWS EC2 Instance Metadata Service endpoint'
    tags: [cloud, aws, ssrf, metadata]

  - name: cloud_metadata_gcp
    severity: high
    pattern: 'metadata\.google\.internal'
    description: 'GCP Compute Engine metadata endpoint'
    tags: [cloud, gcp, ssrf, metadata]

  - name: cloud_metadata_azure
    severity: high
    pattern: '169\.254\.169\.254/metadata/instance'
    description: 'Azure Instance Metadata Service endpoint'
    tags: [cloud, azure, ssrf, metadata]
```

- [ ] **Step 2: Add 6 .env rules**

Append to `internal/rules/builtin.yaml`:

```yaml
  # --- Environment Variable Secrets ---
  - name: env_sensitive_var
    severity: high
    pattern: '(?:^|\s)(?:DATABASE_URL|REDIS_URL|MONGODB_URI|MONGODB_CONNECTION|MONGO_URI|SUPABASE_URL|SUPABASE_KEY|SUPABASE_SERVICE_KEY)=(.+)'
    description: 'Sensitive environment variable with connection string or URL'
    tags: [env, database, sensitive]

  - name: env_token_var
    severity: high
    pattern: '(?:^|\s)(?:MAILGUN_API_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY|ALGOLIA_API_KEY|ALGOLIA_SEARCH_KEY|STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET|SQUARE_ACCESS_TOKEN)=(.+)'
    description: 'Provider-specific sensitive token in environment variable'
    tags: [env, token, provider]

  - name: env_generic_secret
    severity: medium
    pattern: '(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})'
    description: 'Generic secret/password/token environment variable'
    tags: [env, generic, secret]
    requires_context: true
    context_keywords: [secret, token, password, key, api, auth, access, private]
    entropy_threshold: 3.0

  - name: dotenv_file_secret
    severity: high
    pattern: '(?:^|\s)(?:SECRET|TOKEN|API_KEY|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|DATABASE_URL|REDIS_URL|MONGODB_URI)=(.+)'
    description: 'Sensitive value in .env or dotenv file'
    tags: [env, dotenv, secret]

  - name: env_aws_secret
    severity: critical
    pattern: '(?:^|\s)AWS_SECRET_ACCESS_KEY=(?![\s]*$)(\S+)'
    description: 'AWS Secret Access Key in environment variable'
    tags: [env, aws, cloud]

  - name: npmrc_auth_token
    severity: high
    pattern: '_authToken\s*=\s*(?:ghp_|npm_)?[A-Za-z0-9_-]{20,}'
    description: 'npm auth token in .npmrc file'
    tags: [env, npm, token]
```

- [ ] **Step 3: Run rule tests**

Run: `go test ./internal/rules/ -v -race`
Expected: ALL PASS (existing tests unaffected by new rules)

- [ ] **Step 4: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add 9 detection rules (3 cloud metadata + 6 env secrets)"
```

---

## Task 7: Diff Mode

**Files:**
- Modify: `internal/scanner/scan.go`

- [ ] **Step 1: Add diff filter function**

In `internal/scanner/scan.go`, add at the end of the file:

```go
// FilterNewOnly returns only findings marked as new (IsNew == true).
func FilterNewOnly(findings []finding.Finding) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		if f.IsNew {
			result = append(result, f)
		}
	}
	return result
}
```

- [ ] **Step 2: Write test**

Create (or append to existing test file):

```go
func TestFilterNewOnly(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: true},
		{RuleName: "b", IsNew: false},
		{RuleName: "c", IsNew: true},
	}
	result := FilterNewOnly(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0].RuleName != "a" || result[1].RuleName != "c" {
		t.Errorf("unexpected results: %v", result)
	}
}

func TestFilterNewOnly_AllNew(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: true},
	}
	result := FilterNewOnly(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
}

func TestFilterNewOnly_NoneNew(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: false},
	}
	result := FilterNewOnly(findings)
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/scanner/ -run TestFilterNewOnly -v -race`
Expected: PASS

- [ ] **Step 4: Wire diff filter into scan pipeline**

In `cmd/scan.go`, find where findings are filtered by severity (search for `MinSeverity`). After the severity filter, add:

```go
// Diff mode: only show new findings
if diffMode {
    findings = scanner.FilterNewOnly(findings)
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scan.go cmd/scan.go
git commit -m "feat(diff): add --diff mode to filter new findings only"
```

---

## Task 8: JSONL Formatter

**Files:**
- Create: `internal/formatters/jsonl.go`
- Create: `internal/formatters/jsonl_test.go`
- Modify: `internal/formatters/formatter.go`

- [ ] **Step 1: Write failing test**

Create `internal/formatters/jsonl_test.go`:

```go
package formatters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestJSONLFormatter_OneLinePerFinding(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test_rule", Severity: finding.SeverityHigh, Secret: "abc123", Line: 1},
		{File: "b.js", RuleName: "test_rule2", Severity: finding.SeverityCritical, Secret: "xyz789", Line: 5},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %s", len(lines), output)
	}

	// Each line should be valid JSON
	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d: not valid JSON: %v", i, err)
		}
	}
}

func TestJSONLFormatter_NoWrappingArray(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test", Severity: finding.SeverityLow, Secret: "x", Line: 1},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		t.Error("JSONL should not start with array bracket")
	}
}

func TestJSONLFormatter_EmptyFindings(t *testing.T) {
	f := &JSONLFormatter{}
	output, err := f.Format(nil, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output) != "" {
		t.Errorf("expected empty output, got %q", output)
	}
}

func TestJSONLFormatter_Redact(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test", Severity: finding.SeverityHigh, Secret: "supersecret123", Line: 1},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "supersecret123") {
		t.Error("secret should be redacted")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/formatters/ -run TestJSONLFormatter -v`
Expected: FAIL — `JSONLFormatter` not defined

- [ ] **Step 3: Implement JSONL formatter**

Create `internal/formatters/jsonl.go`:

```go
package formatters

import (
	"encoding/json"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type jsonlFinding struct {
	File              string  `json:"file"`
	Line              int     `json:"line"`
	Column            int     `json:"column,omitempty"`
	Rule              string  `json:"rule"`
	Severity          string  `json:"severity"`
	Secret            string  `json:"secret"`
	Entropy           float64 `json:"entropy,omitempty"`
	Context           string  `json:"context,omitempty"`
	Confidence        int     `json:"confidence,omitempty"`
	Verification      string  `json:"verification,omitempty"`
	AdaptiveModifier  int     `json:"adaptive_modifier,omitempty"`
	LearningTier      string  `json:"learning_tier,omitempty"`
}

type JSONLFormatter struct{}

func (f *JSONLFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	if len(findings) == 0 {
		return "", nil
	}

	var sb strings.Builder
	for i, finding := range findings {
		secret := finding.Secret
		if opts.Redact {
			secret = RedactSecret(secret)
		}
		context := finding.Context
		if opts.Redact && context != "" {
			context = strings.Replace(context, finding.Secret, secret, -1)
		}

		jf := jsonlFinding{
			File:             finding.File,
			Line:             finding.Line,
			Column:           finding.Column,
			Rule:             finding.RuleName,
			Severity:         finding.SeverityNames[finding.Severity],
			Secret:           secret,
			Entropy:          finding.Entropy,
			Context:          context,
			Confidence:       finding.Confidence,
			Verification:     finding.VerificationStatus,
			AdaptiveModifier: finding.AdaptiveModifier,
			LearningTier:     finding.LearningTier,
		}

		data, err := json.Marshal(jf)
		if err != nil {
			return "", err
		}
		sb.Write(data)
		if i < len(findings)-1 {
			sb.WriteByte('\n')
		}
	}

	return sb.String(), nil
}
```

- [ ] **Step 4: Register in formatter factory**

In `internal/formatters/formatter.go`, add to the `New` function:

```go
func New(name string) Formatter {
	switch name {
	case "json":
		return &JSONFormatter{}
	case "jsonl", "ndjson":
		return &JSONLFormatter{}
	case "sarif":
		return &SARIFFormatter{}
	case "markdown", "md":
		return &MarkdownFormatter{}
	case "csv":
		return &CSVFormatter{}
	case "html":
		return &HTMLFormatter{}
	default:
		return &TextFormatter{}
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/formatters/ -run TestJSONLFormatter -v -race`
Expected: PASS

- [ ] **Step 6: Update format flag help text**

In `cmd/scan.go`, update the format flag description:

```go
scanCmd.Flags().StringVarP(&formatStr, "format", "f", "text", "output format (text, json, jsonl, sarif, markdown, csv, html)")
```

- [ ] **Step 7: Commit**

```bash
git add internal/formatters/jsonl.go internal/formatters/jsonl_test.go internal/formatters/formatter.go cmd/scan.go
git commit -m "feat(formatters): add JSONL/NDJSON output format for jq piping"
```

---

## Task 9: Cookie Parser + Wire Headers into Crawl

**Files:**
- Create: `internal/scanner/cookie_parser.go`
- Create: `internal/scanner/cookie_parser_test.go`
- Modify: `internal/scanner/scan.go` (wire headers + cookies into crawl)

- [ ] **Step 1: Write failing test**

Create `internal/scanner/cookie_parser_test.go`:

```go
package scanner

import (
	"net/http"
	"testing"
)

func TestParseCookies_Simple(t *testing.T) {
	cookies := ParseCookies("session=abc123; csrftoken=xyz789")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "session" || cookies[0].Value != "abc123" {
		t.Errorf("cookie[0]: got %s=%s", cookies[0].Name, cookies[0].Value)
	}
	if cookies[1].Name != "csrftoken" || cookies[1].Value != "xyz789" {
		t.Errorf("cookie[1]: got %s=%s", cookies[1].Name, cookies[1].Value)
	}
}

func TestParseCookies_EqualsInValue(t *testing.T) {
	cookies := ParseCookies("token=abc=def=ghi")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Value != "abc=def=ghi" {
		t.Errorf("expected value 'abc=def=ghi', got %q", cookies[0].Value)
	}
}

func TestParseCookies_Empty(t *testing.T) {
	cookies := ParseCookies("")
	if len(cookies) != 0 {
		t.Fatalf("expected 0 cookies, got %d", len(cookies))
	}
}

func TestParseCookies_LeadingTrailingSpaces(t *testing.T) {
	cookies := ParseCookies("  a=1 ;  b=2  ")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}
	if cookies[0].Name != "a" || cookies[0].Value != "1" {
		t.Errorf("cookie[0]: got %s=%s", cookies[0].Name, cookies[0].Value)
	}
}

func TestParseCookies_SingleCookie(t *testing.T) {
	cookies := ParseCookies("session=abc")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
}

func TestParseCookies_HttpCookieType(t *testing.T) {
	cookies := ParseCookies("a=1; b=2")
	for _, c := range cookies {
		if _, ok := c.(*http.Cookie); !ok {
			t.Errorf("expected *http.Cookie, got %T", c)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestParseCookies -v`
Expected: FAIL — `ParseCookies` not defined

- [ ] **Step 3: Implement cookie parser**

Create `internal/scanner/cookie_parser.go`:

```go
package scanner

import (
	"net/http"
	"strings"
)

// ParseCookies parses a browser-style cookie header string ("name1=value1; name2=value2")
// into individual *http.Cookie values. Uses a custom parser because Go's
// http.ParseCookie is designed for Set-Cookie headers, not Cookie request headers.
func ParseCookies(cookieStr string) []*http.Cookie {
	if strings.TrimSpace(cookieStr) == "" {
		return nil
	}

	var cookies []*http.Cookie
	// Split on "; " but also handle ";" without space
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Split on first "=" only (value may contain "=")
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(part[:eqIdx])
		value := strings.TrimSpace(part[eqIdx+1:])
		if name == "" {
			continue
		}
		// Strip quotes if present
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: value,
		})
	}
	return cookies
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/scanner/ -run TestParseCookies -v -race`
Expected: PASS

- [ ] **Step 5: Wire headers and cookies into ScanURLs**

In `internal/scanner/scan.go`, find the `ScanURLs` function. After creating the `httpClient`, wrap the transport with headers if present:

```go
// After httpClient creation:
if len(cfg.Headers) > 0 || cfg.CookieString != "" {
    // Build effective headers map
    effectiveHeaders := make(map[string][]string)
    for k, vals := range cfg.Headers {
        effectiveHeaders[k] = vals
    }
    // Inject cookies as Cookie header
    if cfg.CookieString != "" {
        for _, c := range ParseCookies(cfg.CookieString) {
            effectiveHeaders["Cookie"] = append(effectiveHeaders["Cookie"], c.String())
        }
    }
    httpClient.Transport = &headerTransport{
        base:    httpClient.Transport,
        headers: effectiveHeaders,
    }
}
```

- [ ] **Step 6: Run all tests**

Run: `go test -race ./...`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/cookie_parser.go internal/scanner/cookie_parser_test.go internal/scanner/scan.go
git commit -m "feat(scanner): add cookie parser and wire headers/cookies into crawl pipeline"
```

---

## Task 10: Env Var Bindings + Webhook Proxy + Validator Proxy + Documentation

**Files:**
- Modify: `cmd/scan.go` (env bindings are automatic, but verify)
- Modify: `internal/validator/http.go` (call InitValidatorClient from scan)
- Modify: `cmd/scan.go` (call InitValidatorClient + webhook options)

- [ ] **Step 1: Wire validator proxy**

In `cmd/scan.go`, find where `--validate` is handled. Before validation starts, call:

```go
if validate {
    validator.InitValidatorClient(proxyURL)
}
```

- [ ] **Step 2: Wire webhook proxy**

In `cmd/scan.go`, find where `PostWebhook` is called. Add proxy option:

```go
var webhookOpts []formatters.WebhookOption
if proxyURL != "" {
    webhookOpts = append(webhookOpts, formatters.WithProxy(proxyURL))
}
err = formatters.PostWebhook(webhookURL, webhookStyle, findings, webhookOpts...)
```

- [ ] **Step 3: Verify env var bindings work**

Run: `SYCK_SCAN_PROXY=http://test:8080 go run . scan --help 2>&1 | grep proxy`
Expected: proxy flag shows default (env binding is automatic via `bindEnvToFlags`)

Note: The existing `bindEnvToFlags` in `cmd/env.go` automatically binds all flags to `SYCK_SCAN_<FLAG>` env vars. No changes needed to `env.go`.

- [ ] **Step 4: Update README.md**

Add to the CLI Flags section in README.md:

```markdown
### Bug Bounty Flags

| Flag | Description |
|------|-------------|
| `--proxy` | Route all HTTP traffic through a proxy (e.g. Burp Suite at `http://127.0.0.1:8080`) |
| `--auth-token` | Bearer token for authenticated crawling |
| `--header` | Custom header (repeatable): `--header "Name: Value"` |
| `--scope-file` | File with scope regex patterns (one per line, `#` comments) |
| `--cookie` | Cookie string: `--cookie "session=abc; token=xyz"` |
| `--no-sitemap` | Disable robots.txt/sitemap.xml discovery |
| `--diff` | Only show new findings (requires `--cache-db`) |
| `--http-timeout` | HTTP timeout (default `10s`) |
```

- [ ] **Step 5: Run all tests**

Run: `go test -race ./...` and `go vet ./...`
Expected: ALL PASS

- [ ] **Step 6: Build and smoke test**

Run: `go build -o /tmp/syck . && /tmp/syck scan --help`
Expected: All 8 new flags visible in help output

- [ ] **Step 7: Commit**

```bash
git add cmd/scan.go internal/validator/http.go README.md
git commit -m "feat: wire validator/webhook proxy, update docs for V1.5 flags"
```

---

## Task 11: Final Verification + Integration Tests

**Files:**
- Create: `internal/httpclient/integration_test.go`

- [ ] **Step 1: Run full test suite**

Run: `go test -race ./... -timeout 120s`
Expected: ALL PASS

- [ ] **Step 2: Run vet + format**

Run: `go vet ./...` and `gofmt -l .`
Expected: clean

- [ ] **Step 3: Build binary**

Run: `go build -o /tmp/syck .`
Expected: builds successfully

- [ ] **Step 4: Smoke test with proxy flag**

Run: `/tmp/syck scan --help 2>&1 | grep -E "(proxy|auth-token|scope-file|cookie|no-sitemap|diff|http-timeout|header)"`
Expected: All 8 flags listed

- [ ] **Step 5: Smoke test JSONL format**

Run: `echo 'AKIAIOSFODNN7EXAMPLE' | /tmp/syck scan --pipe -f jsonl --no-color 2>/dev/null`
Expected: One JSON object per line on stdout

- [ ] **Step 6: Smoke test sitemap discovery**

Run: `/tmp/syck scan -u https://httpbin.org/robots.txt --no-color -q 2>&1 | head -5`
Expected: Scan completes without error (robots.txt is fetched)

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: V1.5 bug bounty core final verification"
```
