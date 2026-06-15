# Technology Fingerprinting — Design Spec

**Version:** 1.0  
**Date:** 2026-06-15  
**Status:** Approved

---

## 1. Overview

Add technology stack detection to syck's recon pipeline. Detects frameworks, CMS, languages, servers, cloud providers, CDNs, and exposed services from both HTTP responses (URL crawl) and source code (file scan).

**Goal:** Give bug bounty hunters immediate visibility into the target's technology stack, enabling targeted CVE research and attack surface mapping.

---

## 2. Architecture

Two independent detectors following established patterns:

1. **TechFingerprintWeb** — HTTP-based detector implementing `recon.Detector` interface. Analyzes response headers, cookies, and HTML body on unique origins. Wired into `ScanURLs` crawl pipeline.

2. **TechFingerprintSource** — Content analysis function called from `scanContent()`. Detects frameworks from import patterns, package manifests, and config files. Wired into file scan pipeline.

Both share a common detection database but operate independently.

---

## 3. Web Fingerprinting (`detector_techweb.go`)

### 3.1 Request Model

- Same origin deduplication as `SecurityHeaderDetector` (scheme+host+port)
- Single GET request per origin with `Range: bytes=0-0` to minimize bandwidth
- HEAD→GET fallback for unreliable servers
- Body limited to 50KB for HTML analysis
- Gzip decompression support

### 3.2 Confidence Scoring

Each signal contributes confidence points. Findings are reported when cumulative confidence >= 60.

| Signal Source | Confidence |
|---|---|
| X-Powered-By header | 80 |
| Server header (with version) | 60 |
| Meta generator tag | 80 |
| JS global variable (__NEXT_DATA__, etc.) | 80 |
| Cookie name match | 50 |
| Asset path (wp-content/, etc.) | 40 |
| Single HTML string match | 20 |
| XML-RPC endpoint reference | 70 |
| Endpoint path in body (/graphql, etc.) | 60 |

### 3.3 Evidence Collection

Each technology detection accumulates evidence:

```go
type TechEvidence struct {
    Signal string // e.g. "X-Powered-By", "cookie:PHPSESSID", "meta:generator"
}
```

### 3.4 Deduplication

One finding per technology per origin. If PHP is detected from X-Powered-By, PHPSESSID cookie, and body content, merge into a single finding with:
- All evidence strings
- Combined confidence (sum of signal confidences, capped at 99)
- Most specific version extracted

### 3.5 Version Extraction

Extract versions where possible using regex patterns:

| Source | Pattern | Example |
|---|---|---|
| Server header | `Server: nginx/1.24.0` | nginx 1.24.0 |
| X-Powered-By | `X-Powered-By: PHP/8.2.10` | PHP 8.2.10 |
| Meta generator | `<meta generator content="WordPress 6.4">` | WordPress 6.4 |
| jQuery in body | `jquery-3.7.1.min.js` | jQuery 3.7.1 |

### 3.6 Detection Matrix

#### CMS (Severity: HIGH)

| Technology | Signals |
|---|---|
| WordPress | `X-Generator: WordPress`, `<meta generator>`, `wp-content/`, `wp-includes/`, `xmlrpc.php` |
| Drupal | `X-Drupal-Cache`, `<meta generator>`, `sites/default/files/`, `drupal.js` |
| Shopify | `Shopify.theme`, `cdn.shopify.com` |
| Joomla | `<meta generator: Joomla>`, `/administrator/`, `Joomla!` |

#### Frameworks (Severity: MEDIUM)

| Technology | Signals |
|---|---|
| Express | `connect.sid` cookie, `X-Powered-By: Express` |
| Rails | `X-Request-Id` + `X-Runtime`, `_rails_session` cookie |
| Django | `csrftoken` cookie, `csrfmiddlewaretoken` |
| Spring Boot | `X-Application-Context`, `Whitelabel Error Page` |
| Laravel | `laravel_session` cookie, `csrf-token` meta, `/mix-manifest.json` |
| ASP.NET | `X-Powered-By: ASP.NET`, `X-AspNet-Version`, `ASP.NET_SessionId` |
| ASP.NET Core | `Server: Kestrel`, `.AspNetCore.Session`, `__RequestVerificationToken` |
| Next.js | `window.__NEXT_DATA__`, `__next/` |
| Nuxt.js | `__NUXT__` |
| Remix | `window.__remixContext` |
| Hugo | `<meta generator: Hugo>` |
| Jekyll | `<meta generator: Jekyll>` |

#### Languages/Servers (Severity: LOW)

| Technology | Signals |
|---|---|
| PHP | `X-Powered-By: PHP`, `PHPSESSID` |
| Java | `JSESSIONID` |
| Python/Flask | `session=` cookie, `Werkzeug`, Python tracebacks |
| FastAPI | `/swagger-ui`, `/redoc`, `/openapi.json`, `server: uvicorn` |
| Nginx | version from `Server` header |
| Apache | version from `Server` header |

#### Infrastructure (Severity: LOW)

| Technology | Signals |
|---|---|
| AWS | `x-amz-request-id`, `x-amz-id-2` |
| CloudFront | `x-cache: Hit from cloudfront` |
| Azure | `x-ms-request-id` |
| GCP | `x-goog-generation` |
| Cloudflare | `cf-ray`, `cf-cache-status` |
| Akamai | `akamai-origin-hop` |
| Fastly | `x-served-by` |
| Varnish | `via: varnish` |

#### Exposed Services (Severity: HIGH)

| Technology | Signals |
|---|---|
| Kubernetes API | `X-Kubernetes-Pf-Flowschema-Uid`, `"kind":"Status"` in body |
| GraphQL | `/graphql`, `/graphiql`, `graphiql` in body, Apollo references |

### 3.7 Output

```go
type TechEvidence struct {
    Signal string
}

type TechFindResult struct {
    URL        string
    Technology string
    Version    string
    Category   string // cms, framework, language, library, server, infrastructure, exposed
    Confidence int
    Evidence   []TechEvidence
    Severity   finding.Severity
}
```

Mapped to `finding.Finding` with:
- `RuleName`: `"tech_" + category + "_" + technology` (e.g. `tech_framework_laravel`)
- `Severity`: from detection matrix
- `ConfidenceBand`: computed from confidence score
- `Context`: technology + version + evidence list
- `Secret`: technology name (for display)

---

## 4. Source Fingerprinting (`techsource.go`)

### 4.1 Trigger

Called from `scanContent()` after rule matching. Only runs on specific file types:
- `package.json`, `composer.json`, `Gemfile`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`
- Config files: `next.config.js`, `nuxt.config.js`, `gatsby-config.js`, `wp-config.php`, `django/settings.py`, `config/database.yml`
- JS/TS files (for import pattern matching): `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.mjs`

### 4.2 Detection Signals

*Package manifests:*

| File | Pattern | Technology | Category |
|---|---|---|---|
| `package.json` | `"next":` | Next.js | framework |
| `package.json` | `"nuxt":` | Nuxt.js | framework |
| `package.json` | `"gatsby":` | Gatsby | framework |
| `package.json` | `"express":` | Express | framework |
| `package.json` | `"react":` | React | library |
| `package.json` | `"vue":` | Vue.js | library |
| `package.json` | `"@angular/core":` | Angular | library |
| `composer.json` | `"laravel/framework":` | Laravel | framework |
| `Gemfile` | `gem 'rails'` | Rails | framework |
| `requirements.txt` | `Django` | Django | framework |
| `requirements.txt` | `Flask` | Flask | framework |
| `go.mod` | `gin-gonic/gin` | Gin | framework |
| `go.mod` | `gorilla/mux` | Gorilla | framework |
| `Cargo.toml` | `actix-web` | Actix | framework |
| `Cargo.toml` | `axum` | Axum | framework |
| `pom.xml` | `spring-boot` | Spring Boot | framework |
| `build.gradle` | `spring-boot` | Spring Boot | framework |

*Config files:*

| File | Technology | Category |
|---|---|---|
| `next.config.js` / `next.config.mjs` | Next.js | framework |
| `nuxt.config.js` / `nuxt.config.ts` | Nuxt.js | framework |
| `gatsby-config.js` | Gatsby | framework |
| `wp-config.php` | WordPress | cms |
| `django/settings.py` | Django | framework |
| `config/database.yml` | Rails | framework |

*Import patterns (JS/TS):*

| Pattern | Technology | Category |
|---|---|---|
| `from 'react'` / `require('react')` | React | library |
| `from 'vue'` | Vue.js | library |
| `from '@angular'` / `@Component` | Angular | library |
| `from 'express'` | Express | framework |
| `from 'next/'` | Next.js | framework |
| `import Flask` | Flask | framework |
| `from django` | Django | framework |

### 4.3 Severity

Same as web detector. One finding per technology per file.

### 4.4 Output

Returns `[]finding.Finding` with:
- `RuleName`: `"tech_source_" + technology` (e.g. `tech_source_laravel`)
- `File`: source file path
- `Line`: 1 (file-level detection)
- `Severity`: from detection matrix
- `Context`: technology + detection source

---

## 5. CLI Integration

### 5.1 Flag

`--tech-detect` (default: `true`, `--no-tech-detect` to disable)

Controls both web and source fingerprinting. When disabled, neither detector runs.

### 5.2 Wiring

- **Web detector:** Registered in `stage_collector.go` when `cfg.TechDetect` is true. Also invoked directly in `ScanURLs` after crawl (same pattern as SecurityHeaderDetector).
- **Source detector:** Called from `scanContent()` when `cfg.TechDetect` is true and file matches trigger types.

### 5.3 Scanner Config

```go
// In scanner.Config
TechDetect bool
```

---

## 6. Output Format Integration

All 6 formatters display tech findings:

- **Text:** `[tech] WordPress 6.4 [cms] confidence=80 evidence=[meta:generator, wp-content/]`
- **JSON:** `technology`, `version`, `category`, `confidence`, `evidence` fields on finding
- **SARIF:** `technology` property on result
- **Markdown:** Technology, Version, Category columns
- **CSV:** `technology,version,category,confidence` columns
- **HTML:** Technology, Version, Category columns

---

## 7. Testing Strategy

### Unit Tests

- `detector_techweb_test.go`: 30+ tests
  - Confidence scoring thresholds (below/above 60)
  - Version extraction regex patterns
  - Evidence deduplication
  - Each technology category (CMS, framework, language, infrastructure, exposed)
  - Origin deduplication
  - HEAD→GET fallback
  - Gzip body decompression
  - False positive rejection (e.g. `wp-content` in non-WordPress context)

- `techsource_test.go`: 20+ tests
  - Each package manifest pattern
  - Each config file detection
  - Each import pattern
  - File type filtering (only trigger files)
  - Multiple technologies in one file

### Integration Test

- 3 httptest.NewServer instances: WordPress site, Express API, bare Nginx
- Verify correct technology detection per server
- Verify confidence thresholds
- Verify deduplication (one finding per technology)

---

## 8. Files to Create/Modify

| File | Action | Purpose |
|---|---|---|
| `internal/recon/detector_techweb.go` | Create | Web fingerprinting detector |
| `internal/recon/detector_techweb_test.go` | Create | Web detector tests |
| `internal/scanner/techsource.go` | Create | Source code fingerprinting |
| `internal/scanner/techsource_test.go` | Create | Source detector tests |
| `internal/scanner/scanner.go` | Modify | Add `TechDetect bool` to Config |
| `internal/scanner/scan.go` | Modify | Wire source detector into scanContent, web detector into ScanURLs |
| `internal/scanner/stage_collector.go` | Modify | Register web detector |
| `cmd/scan.go` | Modify | Add `--tech-detect` flag, wire to Config |

---

## 9. Future Work (V2)

- Fingerprint database in YAML for easy extension
- CVE correlation (version → known vulnerabilities)
- Wappalyzer-style weighted scoring
- Technology age/end-of-life detection
- License detection from package manifests
