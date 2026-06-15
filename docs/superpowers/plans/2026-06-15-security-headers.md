# Security Header Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HTTP security header analysis to the recon framework — 18 finding types covering CSP, HSTS, CORS, cookies, XFO, XCTO, Referrer-Policy, Permissions-Policy, server info disclosure, and security.txt.

**Architecture:** New `SecurityHeaderDetector` in `internal/recon/detector_headers.go` implements the existing `Detector` interface. Makes HEAD→GET fallback requests to discovered URLs, deduplicates by origin, and returns structured findings. Self-contained — no crawler modifications needed.

**Tech Stack:** Go standard library (`net/http`, `net/url`, `strings`, `regexp`), existing `httpclient.NewClient` factory, existing `finding.Severity` types.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `internal/recon/detector_headers.go` | SecurityHeaderDetector, fetchHeaders, origin dedup, all 18 checks |
| Create | `internal/recon/detector_headers_test.go` | 27 tests using httptest.NewServer |
| Modify | `internal/scanner/scanner.go:17-71` | Add `HeaderCheck bool` to Config struct |
| Modify | `internal/scanner/stage_collector.go:20-38` | Register SecurityHeaderDetector when HeaderCheck enabled |
| Modify | `cmd/scan.go:53-117` | Add `headerCheck` flag var |
| Modify | `cmd/scan.go:119-185` | Register `--header-check` flag |
| Modify | `cmd/scan.go:342-392` | Wire HeaderCheck into scanner.Config |

---

## Task 1: Core Infrastructure — Detector, HEAD→GET, Origin Dedup

**Files:**
- Create: `internal/recon/detector_headers.go`
- Create: `internal/recon/detector_headers_test.go`

- [ ] **Step 1: Write failing tests for core infrastructure**

Create `internal/recon/detector_headers_test.go`:

```go
package recon

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectOrigin(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/path", "https://example.com"},
		{"https://example.com:8443/path", "https://example.com:8443"},
		{"http://localhost:3000/", "http://localhost:3000"},
		{"https://example.com", "https://example.com"},
	}
	for _, tt := range tests {
		got := detectOrigin(tt.url)
		if got != tt.want {
			t.Errorf("detectOrigin(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestFetchHeaders_HEAD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	hdr, cookies, status, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if hdr.Get("Content-Security-Policy") != "default-src 'self'" {
		t.Errorf("CSP = %q, want %q", hdr.Get("Content-Security-Policy"), "default-src 'self'")
	}
	if len(cookies) != 0 {
		t.Errorf("cookies = %d, want 0", len(cookies))
	}
}

func TestFetchHeaders_HEADFallbackToGET(t *testing.T) {
	getCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(405)
			return
		}
		getCalled = true
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	hdr, _, status, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if !getCalled {
		t.Error("GET fallback not called after HEAD 405")
	}
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if hdr.Get("X-Frame-Options") != "DENY" {
		t.Errorf("XFO = %q, want DENY", hdr.Get("X-Frame-Options"))
	}
}

func TestFetchHeaders_CookiesParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := srv.Client()
	_, cookies, _, err := fetchHeaders(client, srv.URL)
	if err != nil {
		t.Fatalf("fetchHeaders: %v", err)
	}
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want 2", len(cookies))
	}
	if cookies[0].Name != "session" || cookies[0].Value != "abc123" {
		t.Errorf("cookie[0] = %s=%s, want session=abc123", cookies[0].Name, cookies[0].Value)
	}
	if !cookies[0].Secure {
		t.Error("cookie[0].Secure = false, want true")
	}
}

func TestSecurityHeaderDetector_DeduplicatesByOrigin(t *testing.T) {
	checkCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkCount++
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	// 3 URLs on same origin — should only check once
	urls := []string{
		srv.URL + "/",
		srv.URL + "/about",
		srv.URL + "/login",
	}
	findings := d.Detect(urls)

	_ = findings // check count matters here
	if checkCount != 1 {
		t.Errorf("checkCount = %d, want 1 (host-level dedup)", checkCount)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/recon/ -run "TestDetectOrigin|TestFetchHeaders|TestSecurityHeaderDetector_Dedup" -v`
Expected: FAIL — `undefined: detectOrigin, fetchHeaders, NewSecurityHeaderDetector`

- [ ] **Step 3: Write minimal implementation**

Create `internal/recon/detector_headers.go`:

```go
package recon

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

// SecurityHeaderDetector analyzes HTTP security headers on discovered URLs.
type SecurityHeaderDetector struct {
	client *http.Client
}

// NewSecurityHeaderDetector creates a detector that checks security headers
// using the provided HTTP client.
func NewSecurityHeaderDetector(client *http.Client) *SecurityHeaderDetector {
	return &SecurityHeaderDetector{client: client}
}

// Detect checks security headers on unique origins for the given URLs.
func (d *SecurityHeaderDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	seen := make(map[string]bool)

	for _, u := range urls {
		origin := detectOrigin(u)
		if origin == "" || seen[origin] {
			continue
		}
		seen[origin] = true

		hdr, cookies, status, err := fetchHeaders(d.client, u)
		if err != nil || status >= 500 {
			continue
		}

		isHTTPS := strings.HasPrefix(u, "https://")
		out = append(out, d.checkHeaders(origin, u, hdr, cookies, isHTTPS)...)
	}

	return out
}

// detectOrigin extracts scheme://host[:port] for deduplication.
func detectOrigin(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if parsed.Host == "" {
		return ""
	}
	origin := parsed.Scheme + "://" + parsed.Host
	return origin
}

// fetchHeaders makes a HEAD request (falling back to GET on failure) and
// returns response headers, parsed cookies, status code, and error.
func fetchHeaders(client *http.Client, rawURL string) (http.Header, []*http.Cookie, int, error) {
	// Try HEAD first
	status, hdr, cookies, err := doRequest(client, "HEAD", rawURL)
	if err == nil && status != 405 && status != 403 && status < 500 {
		return hdr, cookies, status, nil
	}

	// Fallback to GET with Range header to minimize bandwidth
	status, hdr, cookies, err = doRequest(client, "GET", rawURL)
	if err != nil {
		return nil, nil, 0, err
	}
	return hdr, cookies, status, nil
}

func doRequest(client *http.Client, method, rawURL string) (int, http.Header, []*http.Cookie, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if method == "GET" {
		req.Header.Set("Range", "bytes=0-0")
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	// Consume body to allow connection reuse (but limit reads)
	limitedReader := io.LimitReader(resp.Body, 1024)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, gErr := gzip.NewReader(limitedReader)
		if gErr == nil {
			defer gr.Close()
			limitedReader = gr
		}
	}
	io.Copy(io.Discard, limitedReader)

	return resp.StatusCode, resp.Header, resp.Cookies(), nil
}

// checkHeaders runs all security header checks on a response.
func (d *SecurityHeaderDetector) checkHeaders(origin, url string, headers http.Header, cookies []*http.Cookie, isHTTPS bool) []SurfaceFinding {
	var out []SurfaceFinding

	// CSP
	out = append(out, analyzeCSP(headers)...)

	// HSTS (HTTPS only)
	if isHTTPS {
		out = append(out, analyzeHSTS(headers)...)
	}

	// X-Frame-Options
	out = append(out, analyzeXFO(headers)...)

	// X-Content-Type-Options
	out = append(out, analyzeXCTO(headers)...)

	// Referrer-Policy
	out = append(out, analyzeReferrerPolicy(headers)...)

	// Permissions-Policy
	out = append(out, analyzePermissionsPolicy(headers)...)

	// CORS
	out = append(out, d.analyzeCORS(headers, url)...)

	// Cookies
	if isHTTPS {
		out = append(out, analyzeCookies(cookies)...)
	}

	// Server info disclosure
	out = append(out, analyzeServerInfo(headers)...)

	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/recon/ -run "TestDetectOrigin|TestFetchHeaders|TestSecurityHeaderDetector_Dedup" -v`
Expected: PASS (stubs for analyzeCSP etc. will be needed — create minimal no-op functions)

- [ ] **Step 5: Add stub functions for compilation**

Add to `detector_headers.go`:

```go
func analyzeCSP(headers http.Header) []SurfaceFinding                     { return nil }
func analyzeHSTS(headers http.Header) []SurfaceFinding                     { return nil }
func analyzeXFO(headers http.Header) []SurfaceFinding                      { return nil }
func analyzeXCTO(headers http.Header) []SurfaceFinding                     { return nil }
func analyzeReferrerPolicy(headers http.Header) []SurfaceFinding           { return nil }
func analyzePermissionsPolicy(headers http.Header) []SurfaceFinding        { return nil }
func (d *SecurityHeaderDetector) analyzeCORS(headers http.Header, url string) []SurfaceFinding { return nil }
func analyzeCookies(cookies []*http.Cookie) []SurfaceFinding               { return nil }
func analyzeServerInfo(headers http.Header) []SurfaceFinding               { return nil }
```

- [ ] **Step 6: Commit**

```bash
git add internal/recon/detector_headers.go internal/recon/detector_headers_test.go
git commit -m "feat(recon): add SecurityHeaderDetector core infrastructure"
```

---

## Task 2: CSP + HSTS + XFO Analysis

**Files:**
- Modify: `internal/recon/detector_headers.go` (replace CSP/HSTS/XFO stubs)
- Modify: `internal/recon/detector_headers_test.go`

- [ ] **Step 1: Write failing tests**

Append to `detector_headers_test.go`:

```go
func TestAnalyzeCSP_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeCSP(hdr)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Source != "missing-csp" || findings[0].Severity != finding.SeverityHigh {
		t.Errorf("got %s/%v, want missing-csp/HIGH", findings[0].Source, findings[0].Severity)
	}
}

func TestAnalyzeCSP_UnsafeInline(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-unsafe-inline" && f.Severity == finding.SeverityMedium {
			return // pass
		}
	}
	t.Error("expected weak-csp-unsafe-inline MEDIUM finding")
}

func TestAnalyzeCSP_UnsafeEval(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "script-src 'self' 'unsafe-eval'")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-unsafe-eval" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected weak-csp-unsafe-eval MEDIUM finding")
}

func TestAnalyzeCSP_Wildcard(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src *")
	findings := analyzeCSP(hdr)
	for _, f := range findings {
		if f.Source == "weak-csp-wildcard" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected weak-csp-wildcard MEDIUM finding")
}

func TestAnalyzeCSP_Good(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
	findings := analyzeCSP(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good CSP, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzeHSTS_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeHSTS(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-hsts" {
		t.Errorf("expected missing-hsts, got %v", findings)
	}
}

func TestAnalyzeHSTS_Weak(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Strict-Transport-Security", "max-age=300")
	findings := analyzeHSTS(hdr)
	if len(findings) != 1 || findings[0].Source != "weak-hsts" {
		t.Errorf("expected weak-hsts, got %v", findings)
	}
}

func TestAnalyzeHSTS_Good(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	findings := analyzeHSTS(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good HSTS, got %d", len(findings))
	}
}

func TestAnalyzeXFO_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeXFO(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-xfo" {
		t.Errorf("expected missing-xfo, got %v", findings)
	}
}

func TestAnalyzeXFO_WithCSPFrameAncestors(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Security-Policy", "frame-ancestors 'self'")
	findings := analyzeXFO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when CSP has frame-ancestors, got %d", len(findings))
	}
}

func TestAnalyzeXFO_Present(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Frame-Options", "DENY")
	findings := analyzeXFO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/recon/ -run "TestAnalyzeCSP|TestAnalyzeHSTS|TestAnalyzeXFO" -v`
Expected: FAIL — stub functions return nil, no findings generated

- [ ] **Step 3: Implement CSP + HSTS + XFO analysis**

Replace stubs in `detector_headers.go`:

```go
var cspWeakInlineRE = regexp.MustCompile(`'unsafe-inline'`)
var cspWeakEvalRE = regexp.MustCompile(`'unsafe-eval'`)

func analyzeCSP(headers http.Header) []SurfaceFinding {
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityHigh, Source: "missing-csp"}}
	}

	var out []SurfaceFinding
	if strings.Contains(csp, "default-src *") || strings.Contains(csp, "script-src *") {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-wildcard"})
	}
	if cspWeakInlineRE.MatchString(csp) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-unsafe-inline"})
	}
	if cspWeakEvalRE.MatchString(csp) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "weak-csp-unsafe-eval"})
	}
	return out
}

func analyzeHSTS(headers http.Header) []SurfaceFinding {
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityMedium, Source: "missing-hsts"}}
	}

	// Parse max-age
	idx := strings.Index(hsts, "max-age=")
	if idx >= 0 {
		val := hsts[idx+8:]
		if end := strings.IndexAny(val, ";, "); end >= 0 {
			val = val[:end]
		}
		if age, err := strconv.Atoi(val); err == nil && age < 31536000 {
			return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityLow, Source: "weak-hsts"}}
		}
	}
	return nil
}

func analyzeXFO(headers http.Header) []SurfaceFinding {
	if headers.Get("X-Frame-Options") != "" {
		return nil
	}
	// Check if CSP has frame-ancestors
	csp := headers.Get("Content-Security-Policy")
	if strings.Contains(csp, "frame-ancestors") {
		return nil
	}
	return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityMedium, Source: "missing-xfo"}}
}
```

Add `import "strconv"` to the import block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/recon/ -run "TestAnalyzeCSP|TestAnalyzeHSTS|TestAnalyzeXFO" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/recon/detector_headers.go internal/recon/detector_headers_test.go
git commit -m "feat(recon): add CSP, HSTS, X-Frame-Options analysis"
```

---

## Task 3: CORS Analysis with Origin Reflection

**Files:**
- Modify: `internal/recon/detector_headers.go` (replace CORS stub)
- Modify: `internal/recon/detector_headers_test.go`

- [ ] **Step 1: Write failing tests**

Append to `detector_headers_test.go`:

```go
func TestAnalyzeCORS_Wildcard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-wildcard" && f.Severity == finding.SeverityMedium {
			return
		}
	}
	t.Error("expected cors-wildcard MEDIUM")
}

func TestAnalyzeCORS_WildcardCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-wildcard-credentials" && f.Severity == finding.SeverityHigh {
			return
		}
	}
	t.Error("expected cors-wildcard-credentials HIGH")
}

func TestAnalyzeCORS_OriginReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	for _, f := range findings {
		if f.Source == "cors-origin-reflection" && f.Severity == finding.SeverityHigh {
			return
		}
	}
	t.Error("expected cors-origin-reflection HIGH")
}

func TestAnalyzeCORS_SafeOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	hdr, _, _, _ := fetchHeaders(d.client, srv.URL)
	findings := d.analyzeCORS(hdr, srv.URL)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for safe CORS, got %d: %v", len(findings), findings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/recon/ -run "TestAnalyzeCORS" -v`
Expected: FAIL — stub returns nil

- [ ] **Step 3: Implement CORS analysis**

Replace the CORS stub in `detector_headers.go`:

```go
func (d *SecurityHeaderDetector) analyzeCORS(headers http.Header, url string) []SurfaceFinding {
	acao := headers.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}

	var out []SurfaceFinding
	acac := strings.ToLower(headers.Get("Access-Control-Allow-Credentials"))

	if acao == "*" {
		if acac == "true" {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityHigh, Source: "cors-wildcard-credentials"})
		} else {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "cors-wildcard"})
		}
		return out
	}

	// Test origin reflection
	if detectOriginReflection(d.client, url) {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityHigh, Source: "cors-origin-reflection"})
	}

	return out
}

func detectOriginReflection(client *http.Client, targetURL string) bool {
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	return acao == "https://evil.example.com"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/recon/ -run "TestAnalyzeCORS" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/recon/detector_headers.go internal/recon/detector_headers_test.go
git commit -m "feat(recon): add CORS analysis with origin reflection detection"
```

---

## Task 4: XCTO + Referrer-Policy + Permissions-Policy + Cookies + Server Info

**Files:**
- Modify: `internal/recon/detector_headers.go` (replace remaining stubs)
- Modify: `internal/recon/detector_headers_test.go`

- [ ] **Step 1: Write failing tests**

Append to `detector_headers_test.go`:

```go
func TestAnalyzeXCTO_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeXCTO(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-xcto" {
		t.Errorf("expected missing-xcto, got %v", findings)
	}
}

func TestAnalyzeXCTO_Present(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Content-Type-Options", "nosniff")
	findings := analyzeXCTO(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAnalyzeReferrerPolicy_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzeReferrerPolicy(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-referrer-policy" || findings[0].Severity != finding.SeverityInfo {
		t.Errorf("expected missing-referrer-policy INFO, got %v", findings)
	}
}

func TestAnalyzePermissionsPolicy_Missing(t *testing.T) {
	hdr := http.Header{}
	findings := analyzePermissionsPolicy(hdr)
	if len(findings) != 1 || findings[0].Source != "missing-permissions-policy" || findings[0].Severity != finding.SeverityInfo {
		t.Errorf("expected missing-permissions-policy INFO, got %v", findings)
	}
}

func TestAnalyzeCookies_NoSecure(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc"}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-secure" {
			return
		}
	}
	t.Error("expected cookie-no-secure")
}

func TestAnalyzeCookies_NoHttpOnly(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc", Secure: true}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-httponly" {
			return
		}
	}
	t.Error("expected cookie-no-httponly")
}

func TestAnalyzeCookies_NoSameSite(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc", Secure: true, HttpOnly: true}}
	findings := analyzeCookies(cookies)
	for _, f := range findings {
		if f.Source == "cookie-no-samesite" {
			return
		}
	}
	t.Error("expected cookie-no-samesite")
}

func TestAnalyzeCookies_Good(t *testing.T) {
	cookies := []*http.Cookie{{
		Name:     "session",
		Value:    "abc",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}}
	findings := analyzeCookies(cookies)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for good cookie, got %d: %v", len(findings), findings)
	}
}

func TestAnalyzeServerInfo_ServerVersion(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Server", "Apache/2.4.12")
	findings := analyzeServerInfo(hdr)
	for _, f := range findings {
		if f.Source == "server-version-disclosure" {
			return
		}
	}
	t.Error("expected server-version-disclosure")
}

func TestAnalyzeServerInfo_XPoweredBy(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("X-Powered-By", "PHP/5.6")
	findings := analyzeServerInfo(hdr)
	for _, f := range findings {
		if f.Source == "x-powered-by-disclosure" {
			return
		}
	}
	t.Error("expected x-powered-by-disclosure")
}

func TestAnalyzeServerInfo_NoVersion(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Server", "nginx")
	findings := analyzeServerInfo(hdr)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for versionless Server header, got %d", len(findings))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/recon/ -run "TestAnalyzeXCTO|TestAnalyzeReferrer|TestAnalyzePermissions|TestAnalyzeCookies|TestAnalyzeServerInfo" -v`
Expected: FAIL — stub functions return nil

- [ ] **Step 3: Implement all remaining analyses**

Replace stubs in `detector_headers.go`:

```go
var versionRE = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

func analyzeXCTO(headers http.Header) []SurfaceFinding {
	if headers.Get("X-Content-Type-Options") == "nosniff" {
		return nil
	}
	return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityLow, Source: "missing-xcto"}}
}

func analyzeReferrerPolicy(headers http.Header) []SurfaceFinding {
	if headers.Get("Referrer-Policy") == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-referrer-policy"}}
	}
	return nil
}

func analyzePermissionsPolicy(headers http.Header) []SurfaceFinding {
	if headers.Get("Permissions-Policy") == "" {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-permissions-policy"}}
	}
	return nil
}

func analyzeCookies(cookies []*http.Cookie) []SurfaceFinding {
	var out []SurfaceFinding
	hasSecure, hasHttpOnly, hasSameSite := false, false, false
	for _, c := range cookies {
		if c.Secure {
			hasSecure = true
		}
		if c.HttpOnly {
			hasHttpOnly = true
		}
		if c.SameSite != http.SameSiteDefaultMode {
			hasSameSite = true
		}
	}
	if len(cookies) > 0 && !hasSecure {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityMedium, Source: "cookie-no-secure"})
	}
	if len(cookies) > 0 && !hasHttpOnly {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "cookie-no-httponly"})
	}
	if len(cookies) > 0 && !hasSameSite {
		out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "cookie-no-samesite"})
	}
	return out
}

func analyzeServerInfo(headers http.Header) []SurfaceFinding {
	var out []SurfaceFinding
	if server := headers.Get("Server"); server != "" {
		if versionRE.MatchString(server) {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "server-version-disclosure"})
		}
	}
	if xpb := headers.Get("X-Powered-By"); xpb != "" {
		if versionRE.MatchString(xpb) {
			out = append(out, SurfaceFinding{Category: "security-header", Severity: finding.SeverityLow, Source: "x-powered-by-disclosure"})
		}
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/recon/ -run "TestAnalyzeXCTO|TestAnalyzeReferrer|TestAnalyzePermissions|TestAnalyzeCookies|TestAnalyzeServerInfo" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/recon/detector_headers.go internal/recon/detector_headers_test.go
git commit -m "feat(recon): add XCTO, Referrer-Policy, Permissions-Policy, cookie, server info analysis"
```

---

## Task 5: Security.txt Check

**Files:**
- Modify: `internal/recon/detector_headers.go` (add checkSecurityTxt)
- Modify: `internal/recon/detector_headers_test.go`

- [ ] **Step 1: Write failing tests**

Append to `detector_headers_test.go`:

```go
func TestCheckSecurityTxt_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	origin := detectOrigin(srv.URL)
	findings := d.checkSecurityTxt(srv.Client(), origin)
	if len(findings) != 1 || findings[0].Source != "missing-security-txt" {
		t.Errorf("expected missing-security-txt, got %v", findings)
	}
}

func TestCheckSecurityTxt_Present(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.WriteHeader(200)
			w.Write([]byte("Contact: mailto:security@example.com"))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := NewSecurityHeaderDetector(srv.Client())
	origin := detectOrigin(srv.URL)
	findings := d.checkSecurityTxt(srv.Client(), origin)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/recon/ -run "TestCheckSecurityTxt" -v`
Expected: FAIL — `undefined: d.checkSecurityTxt`

- [ ] **Step 3: Implement checkSecurityTxt**

Add to `detector_headers.go`:

```go
func (d *SecurityHeaderDetector) checkSecurityTxt(client *http.Client, origin string) []SurfaceFinding {
	resp, err := client.Get(origin + "/.well-known/security.txt")
	if err != nil {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-security-txt"}}
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	if resp.StatusCode != 200 {
		return []SurfaceFinding{{Category: "security-header", Severity: finding.SeverityInfo, Source: "missing-security-txt"}}
	}
	return nil
}
```

Update `Detect` to call security.txt check at the end of each origin:

```go
// In Detect(), after checkHeaders:
if isHTTPS {
    out = append(out, d.checkSecurityTxt(d.client, origin)...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/recon/ -run "TestCheckSecurityTxt" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/recon/detector_headers.go internal/recon/detector_headers_test.go
git commit -m "feat(recon): add security.txt check for HTTPS origins"
```

---

## Task 6: Integration — Config, CLI Flag, Stage Wiring

**Files:**
- Modify: `internal/scanner/scanner.go:17-71` — add `HeaderCheck bool`
- Modify: `internal/scanner/stage_collector.go:20-38` — register detector
- Modify: `cmd/scan.go:53-117` — add flag var
- Modify: `cmd/scan.go:119-185` — register flag
- Modify: `cmd/scan.go:342-392` — wire config

- [ ] **Step 1: Add HeaderCheck to Config**

In `internal/scanner/scanner.go`, add to Config struct after `NoSitemap bool`:

```go
HeaderCheck bool // analyze HTTP security headers on discovered URLs
```

- [ ] **Step 2: Add flag var to cmd/scan.go**

In `cmd/scan.go`, add after `diffMode bool`:

```go
headerCheck bool
```

- [ ] **Step 3: Register flag in init()**

In `cmd/scan.go` init(), add after the `--diff` flag registration:

```go
scanCmd.Flags().BoolVar(&headerCheck, "header-check", true, "analyze HTTP security headers on discovered URLs (use --no-header-check to disable)")
```

- [ ] **Step 4: Wire into scanner.Config**

In `cmd/scan.go` runScan(), add to the `scanCfg` initialization after `NoSitemap: noSitemap,`:

```go
HeaderCheck:         headerCheck,
```

- [ ] **Step 5: Register detector in stage_collector.go**

In `internal/scanner/stage_collector.go`, update `NewCollectorStage`:

Add `"net/http"` to imports. Add `"github.com/RA000WL/syck/internal/httpclient"` to imports.

After the `AuthDetector` registration, add:

```go
if cfg.HeaderCheck {
    httpClient := httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)
    s.reconReg.Register(recon.NewSecurityHeaderDetector(httpClient))
}
```

- [ ] **Step 6: Build and verify**

Run: `go build ./...`
Expected: Clean build

Run: `go vet ./...`
Expected: Clean

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/stage_collector.go cmd/scan.go
git commit -m "feat(recon): wire SecurityHeaderDetector into scanner pipeline"
```

---

## Task 7: Full Verification + Integration Test

**Files:**
- Modify: `internal/recon/detector_headers_test.go` (end-to-end integration test)

- [ ] **Step 1: Write integration test**

Append to `detector_headers_test.go`:

```go
func TestSecurityHeaderDetector_FullIntegration(t *testing.T) {
	// Use 3 different servers (different origins) to test different header profiles
	// Server 1: missing everything
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srvBad.Close()

	// Server 2: weak CSP + CORS wildcard + cookies + server version
	srvWeak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Add("Set-Cookie", "session=abc123; Path=/")
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(200)
	}))
	defer srvWeak.Close()

	// Server 3: all good headers
	srvGood := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
	}))
	defer srvGood.Close()

	d := NewSecurityHeaderDetector(srvBad.Client())
	urls := []string{
		srvBad.URL + "/",
		srvWeak.URL + "/api",
		srvGood.URL + "/secure",
	}

	findings := d.Detect(urls)
	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	sourceSet := make(map[string]bool)
	for _, f := range findings {
		sourceSet[f.Source] = true
	}

	// Server 1 (bad): missing-csp, missing-xfo, missing-xcto, missing-referrer-policy, missing-permissions-policy
	if !sourceSet["missing-csp"] {
		t.Error("expected missing-csp from bad server")
	}
	if !sourceSet["missing-xfo"] {
		t.Error("expected missing-xfo from bad server")
	}

	// Server 2 (weak): weak-csp-wildcard, weak-csp-unsafe-inline, weak-csp-unsafe-eval, cors-wildcard-credentials, cookie-no-secure, cookie-no-httponly, cookie-no-samesite, server-version-disclosure
	if !sourceSet["weak-csp-wildcard"] {
		t.Error("expected weak-csp-wildcard from weak server")
	}
	if !sourceSet["cors-wildcard-credentials"] {
		t.Error("expected cors-wildcard-credentials from weak server")
	}
	if !sourceSet["cookie-no-secure"] {
		t.Error("expected cookie-no-secure from weak server")
	}
	if !sourceSet["server-version-disclosure"] {
		t.Error("expected server-version-disclosure from weak server")
	}

	// Server 3 (good): x-powered-by-disclosure (Express has version-like pattern)
	// No missing-csp, missing-hsts, etc.
	if sourceSet["missing-csp"] {
		t.Error("good server should not produce missing-csp")
	}
	if sourceSet["missing-xfo"] {
		t.Error("good server should not produce missing-xfo")
	}
}
```

- [ ] **Step 2: Run full test suite**

Run: `go test -race ./internal/recon/ -v`
Expected: All tests PASS

- [ ] **Step 3: Run full project tests**

Run: `go test -race ./...`
Expected: All packages PASS

- [ ] **Step 4: Build and smoke test**

Run: `go build -o /tmp/syck_headers .`
Run: `/tmp/syck_headers list-rules | head -5`
Expected: Rules listed (no header-specific rules — these are recon findings, not rule matches)

Run: `/tmp/syck_headers scan -u https://example.com --header-check --no-color 2>&1 | head -20`
Expected: Security header findings displayed (missing-csp, missing-hsts, etc.)

- [ ] **Step 5: Verify --no-header-check works**

Run: `/tmp/syck_headers scan -u https://example.com --no-header-check --no-color 2>&1 | grep -c "security-header"`
Expected: 0 (no security header findings)

- [ ] **Step 6: Commit**

```bash
git add internal/recon/detector_headers_test.go
git commit -m "test(recon): add integration test for SecurityHeaderDetector"
```
