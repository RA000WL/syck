# Security Header Analysis — Design Spec

> **Version:** 1.0
> **Date:** 2026-06-15
> **Status:** Approved

## Overview

Add HTTP security header analysis to the recon framework. A new `SecurityHeaderDetector` makes HTTP requests to discovered URLs, inspects response headers and cookies, and produces structured findings for missing, weak, or misconfigured security controls.

This moves SYCK from a "header linter" into a reconnaissance component that surfaces findings bug bounty hunters actually investigate.

## Architecture

### Self-Contained Detector

New file `internal/recon/detector_headers.go`. Implements the existing `Detector` interface (`Detect(urls []string) []SurfaceFinding`). No modifications to the crawler or existing detectors.

### Request Strategy: HEAD → GET Fallback

```
HEAD request
↓
If 405/403/5xx or empty body → GET with Range: bytes=0-0
↓
Analyze response headers
```

Many applications block HEAD, return different headers for HEAD vs GET, or sit behind CDNs that strip headers on HEAD. The GET fallback with `Range: bytes=0-0` minimizes bandwidth while ensuring we get accurate headers.

### Host-Level Deduplication

Deduplicate by `scheme + host[:port]` — NOT by path. HTTP security headers are origin-wide. Checking `/`, `/about`, `/login` separately generates identical findings and massive noise. Each unique origin gets exactly one header check.

### HTTPS-Only Logic

- **HSTS checks:** Only for HTTPS URLs. Missing HSTS on plain HTTP is meaningless.
- **Cookie Secure flag:** Only for HTTPS URLs. HTTP cookies cannot be Secure.
- **Security.txt:** Only for HTTPS URLs. Bug bounty programs are HTTPS.

## Finding Types (18 total)

### Content-Security-Policy (4 findings)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-csp` | HIGH | No `Content-Security-Policy` header present |
| `weak-csp-unsafe-inline` | MEDIUM | CSP contains `'unsafe-inline'` in `script-src` or `style-src` |
| `weak-csp-unsafe-eval` | MEDIUM | CSP contains `'unsafe-eval'` |
| `weak-csp-wildcard` | MEDIUM | `default-src *` or `script-src *` (star as only source) |

CSP analysis should parse the header value and check each directive individually. A CSP like `default-src 'self'; script-src *` should trigger `weak-csp-wildcard` but NOT `weak-csp-unsafe-inline`.

### Strict-Transport-Security (2 findings)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-hsts` | MEDIUM | HTTPS URL with no `Strict-Transport-Security` header |
| `weak-hsts` | LOW | HSTS present but `max-age < 31536000` (1 year) |

### X-Frame-Options (1 finding)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-xfo` | MEDIUM | No `X-Frame-Options` header AND no `frame-ancestors` directive in CSP |

Only flag missing XFO when CSP also lacks `frame-ancestors`. If CSP has `frame-ancestors 'self'`, XFO is redundant.

### X-Content-Type-Options (1 finding)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-xcto` | LOW | No `X-Content-Type-Options: nosniff` header |

### Referrer-Policy (1 finding)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-referrer-policy` | INFO | No `Referrer-Policy` header |

### Permissions-Policy (1 finding)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-permissions-policy` | INFO | No `Permissions-Policy` header |

### CORS (3 findings)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `cors-wildcard` | MEDIUM | `Access-Control-Allow-Origin: *` without credentials |
| `cors-wildcard-credentials` | HIGH | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` |
| `cors-origin-reflection` | HIGH | ACAO reflects the `Origin` request header value back |

**CORS Origin Reflection Test:** For each unique origin, after the initial header check:
1. If ACAO is not `*` and not empty, send a second request with `Origin: https://evil.example.com`
2. If response contains `ACAO: https://evil.example.com` → `cors-origin-reflection` (HIGH)

This is the most valuable CORS check and often finds real bounty issues.

### Cookie Security (3 findings)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `cookie-no-secure` | MEDIUM | `Set-Cookie` without `Secure` flag on HTTPS URL |
| `cookie-no-httponly` | LOW | `Set-Cookie` without `HttpOnly` flag |
| `cookie-no-samesite` | LOW | `Set-Cookie` without `SameSite` attribute |

Check all `Set-Cookie` headers in the response. Report the worst case per cookie attribute across all cookies.

### Server Information Disclosure (2 findings)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `server-version-disclosure` | LOW | `Server` header contains version string (e.g., `Apache/2.4.12`) |
| `x-powered-by-disclosure` | LOW | `X-Powered-By` header present (e.g., `PHP/5.6`) |

Version detection: regex `\d+\.\d+(\.\d+)?` or similar version patterns in `Server` or `X-Powered-By` headers.

### Security.txt (1 finding)

| Finding | Severity | Trigger |
|---------|----------|---------|
| `missing-security-txt` | INFO | HTTPS URL with no `/.well-known/security.txt` accessible (200 status) |

## Implementation

### New File: `internal/recon/detector_headers.go`

```go
package recon

import (
    "net/http"
    "regexp"
    "strings"

    "github.com/RA000WL/syck/internal/finding"
)

type SecurityHeaderDetector struct {
    client *http.Client
}

func NewSecurityHeaderDetector(client *http.Client) *SecurityHeaderDetector {
    return &SecurityHeaderDetector{client: client}
}

func (d *SecurityHeaderDetector) Detect(urls []string) []SurfaceFinding
```

**Internal functions:**
- `detectOrigin(rawURL string) string` — extracts `scheme://host[:port]` for dedup
- `fetchHeaders(client, url) (http.Header, []*http.Cookie, int, error)` — HEAD → GET fallback
- `checkHeaders(origin, url string, headers http.Header, cookies []*http.Cookie, isHTTPS bool) []SurfaceFinding`
- `analyzeCSP(cspValue string) []SurfaceFinding` — parses CSP directives, checks for unsafe-inline/eval/wildcard
- `analyzeCORS(headers http.Header, originURL string) []SurfaceFinding` — checks wildcard, credentials, origin reflection
- `analyzeCookies(cookies []*http.Cookie, isHTTPS bool) []SurfaceFinding` — checks Secure/HttpOnly/SameSite
- `checkSecurityTxt(client *http.Client, origin string) []SurfaceFinding` — GETs /.well-known/security.txt

**CORS reflection detection:**
- `detectOriginReflection(client *http.Client, originURL string, acaoValue string) bool` — sends request with `Origin: https://evil.example.com`, checks if ACAO reflects it

### New File: `internal/recon/detector_headers_test.go`

Tests using `httptest.NewServer`:
- `TestSecurityHeaderDetector_MissingCSP` — no CSP → `missing-csp` HIGH
- `TestSecurityHeaderDetector_WeakCSPUnsafeInline` — CSP with unsafe-inline → `weak-csp-unsafe-inline` MEDIUM
- `TestSecurityHeaderDetector_WeakCSPUnsafeEval` — CSP with unsafe-eval → `weak-csp-unsafe-eval` MEDIUM
- `TestSecurityHeaderDetector_WeakCSPWildcard` — CSP with `script-src *` → `weak-csp-wildcard` MEDIUM
- `TestSecurityHeaderDetector_GoodCSP` — strong CSP → no CSP findings
- `TestSecurityHeaderDetector_MissingHSTS` — HTTPS, no HSTS → `missing-hsts` MEDIUM
- `TestSecurityHeaderDetector_WeakHSTS` — HSTS with low max-age → `weak-hsts` LOW
- `TestSecurityHeaderDetector_GoodHSTS` — strong HSTS → no HSTS findings
- `TestSecurityHeaderDetector_MissingXFO_NoCSPFrameAncestors` — no XFO + no frame-ancestors → `missing-xfo` MEDIUM
- `TestSecurityHeaderDetector_MissingXFO_WithCSPFrameAncestors` — CSP has frame-ancestors → no `missing-xfo`
- `TestSecurityHeaderDetector_MissingXCTO` — no nosniff → `missing-xcto` LOW
- `TestSecurityHeaderDetector_MissingReferrerPolicy` — no header → `missing-referrer-policy` INFO
- `TestSecurityHeaderDetector_MissingPermissionsPolicy` — no header → `missing-permissions-policy` INFO
- `TestSecurityHeaderDetector_CORSWildcard` — ACAO: * → `cors-wildcard` MEDIUM
- `TestSecurityHeaderDetector_CORSWildcardCredentials` — ACAO: * + ACAC: true → `cors-wildcard-credentials` HIGH
- `TestSecurityHeaderDetector_CORSOriginReflection` — ACAO reflects origin → `cors-origin-reflection` HIGH
- `TestSecurityHeaderDetector_CookieNoSecure` — cookie without Secure → `cookie-no-secure` MEDIUM
- `TestSecurityHeaderDetector_CookieNoHttpOnly` — cookie without HttpOnly → `cookie-no-httponly` LOW
- `TestSecurityHeaderDetector_CookieNoSameSite` — cookie without SameSite → `cookie-no-samesite` LOW
- `TestSecurityHeaderDetector_ServerVersionDisclosure` — Server: Apache/2.4.12 → `server-version-disclosure` LOW
- `TestSecurityHeaderDetector_XPoweredByDisclosure` — X-Powered-By: PHP/5.6 → `x-powered-by-disclosure` LOW
- `TestSecurityHeaderDetector_MissingSecurityTxt` — no /.well-known/security.txt → `missing-security-txt` INFO
- `TestSecurityHeaderDetector_HTTPOmitsHSTS` — HTTP URL → no HSTS findings
- `TestSecurityHeaderDetector_HTTPOmitsSecureCookieCheck` — HTTP URL → no cookie-no-secure
- `TestSecurityHeaderDetector_HeadGetFallback` — HEAD returns 405 → falls back to GET
- `TestSecurityHeaderDetector_HostLevelDedup` — 3 paths on same origin → 1 check only

### Modify: `internal/scanner/stage_collector.go`

Register the detector:
```go
s.reconReg.Register(recon.NewSecurityHeaderDetector(httpClient))
```

Guard behind `cfg.HeaderCheck` (default true). Only register when enabled.

### Modify: `internal/scanner/scanner.go`

Add to Config struct:
```go
HeaderCheck bool
```

### Modify: `cmd/scan.go`

Add flag:
```go
var headerCheck bool
```
```go
scanCmd.Flags().BoolVar(&headerCheck, "header-check", true, "Analyze HTTP security headers (use --no-header-check to disable)")
```

Wire into `scanner.Config`.

## Output Format

All findings use category `"security-header"` and source identifies the specific check:

```
[security-header] missing-csp            HIGH     https://example.com
[security-header] cors-wildcard-creds    HIGH     https://api.example.com
[security-header] cors-origin-reflection HIGH     https://app.example.com
[security-header] missing-hsts           MEDIUM   https://example.com
[security-header] cookie-no-secure       MEDIUM   https://example.com
[security-header] weak-hsts              LOW      https://cdn.example.com
[security-header] server-version-disclosure LOW  https://example.com
[security-header] missing-referrer-policy INFO   https://example.com
```

Severity bands match existing SYCK conventions: HIGH/MEDIUM/LOW/INFO.

## Constraints

- **Max 50 unique origins checked** (prevents runaway on huge crawls). Configurable later if needed.
- **10s timeout per request** (reuse `httpclient.NewClient` defaults).
- **CORS reflection test:** Only triggered when ACAO is not `*` and not empty. Adds 1 extra request per origin in that case.
- **Security.txt check:** Only for HTTPS URLs. GETs `/.well-known/security.txt`, considers missing if non-200 response.
- **No false positive escalation:** Missing `Permissions-Policy` and `Referrer-Policy` are INFO, not LOW. These are privacy hardening, not security-critical.
