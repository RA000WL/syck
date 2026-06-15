# Phase 1: Bug Bounty Core — V1.5 Design Spec

> **Version:** 1.3 (final — header multi-value, sitemap limits, diff pipeline, cookie hardening)
> **Date:** 2026-06-15

## Overview

Phase 1 of making SYCK a professional bug bounty tool. Ships 10 components in a single release: shared HTTP client factory, proxy support, authenticated crawling, scope file loading, robots/sitemap discovery, cookie flag, cloud metadata detection, .env rules, diff mode, JSONL output, and configurable HTTP timeouts.

## Components

### 1. Shared HTTP Client Factory + `--proxy` Flag

**Problem:** 9 separate `http.Client{}` creation sites across the codebase with duplicated timeout/redirect/transport config. No way to proxy traffic through Burp Suite.

**Solution:** New `internal/httpclient` package with a factory function.

**Factory signature:**
```go
package httpclient

func NewTransport(proxyURL string, insecureSkipVerify bool) *http.Transport
func NewClient(timeout time.Duration, proxyURL string, insecureSkipVerify bool) *http.Client
```

- `NewTransport` creates an `http.Transport` with `Proxy: http.ProxyURL(proxyURL)` (nil if empty, which falls back to `http.ProxyFromEnvironment` — respects `HTTP_PROXY`/`HTTPS_PROXY` env vars by default)
- `NewClient` creates `&http.Client{Transport: transport, Timeout: timeout, CheckRedirect: defaultRedirectPolicy}`
- `insecureSkipVerify` only used for validator (TLS skip for provider API calls)

**`--proxy` flag:**
- Type: `string`
- Default: `""` (uses env vars)
- Env var: `SYCK_SCAN_PROXY`
- Accepts: `http://host:port`, `https://host:port`, `socks5://host:port`
- Go's `httpproxy` handles `http://user:pass@host:port` natively

**Call sites to update (6 non-test sites):**

| Site | Current | New |
|------|---------|-----|
| `scanner/scan.go:879` (ScanURLs) | `&http.Client{Timeout: 10s}` | `httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)` |
| `crawler/crawler.go:121` (Crawl) | `&http.Client{Timeout: 10s}` | Uses `cfg.HTTPClient` (already injected from ScanURLs) |
| `crawler/juicy.go:61` | `&http.Client{Timeout: 10s}` | `httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)` — needs CrawlConfig access |
| `formatters/webhook.go:43` | `&http.Client{Timeout: 10s}` | `httpclient.NewClient(10*time.Second, proxyURL, false)` — proxyURL passed via FormatOptions |
| `validator/http.go:11` | `&http.Client{Timeout: 5s, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}` | `httpclient.NewClient(5*time.Second, proxyURL, true)` |
| `cmd/upload_sarif.go:82` | `&http.Client{Timeout: 30s}` | `httpclient.NewClient(30*time.Second, proxyURL, false)` — proxyURL from flags |

**Note:** `defaultHTTPClient` at `crawler.go:92` is used by `robots.go:34` as a fallback client — NOT dead code. Keep it but have it use the factory instead.

**Scanner Config additions:**
```go
HTTPTimeout time.Duration  // --http-timeout flag, default 10s
ProxyURL    string         // --proxy flag, default ""
```

### 2. `--auth-token` / `--header` for Authenticated Crawling

**Problem:** Can't scan behind-auth pages. Cookie jar handles session auth, but not Bearer tokens or API key headers.

**Solution:** New CLI flags injected as HTTP headers on all crawl requests.

**Flags:**
- `--auth-token` (string): Shorthand for `--header "Authorization: Bearer <token>"`
- `--header` (string, repeatable): Custom header in `Name: Value` format
- Env vars: `SYCK_SCAN_AUTH_TOKEN`, `SYCK_SCAN_HEADER`

**Implementation:**
- Add `Headers map[string][]string` to `scanner.Config` (multi-value to support duplicate header names)
- Use a `RoundTripper` wrapper to inject headers into all requests:

```go
type headerTransport struct {
    base    http.RoundTripper
    headers map[string][]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    // CRITICAL: Clone request before modifying headers.
    // Modifying the original request causes issues with retries,
    // redirects, and internal http.Client caching.
    cloned := req.Clone(req.Context())
    for k, vals := range t.headers {
        for _, v := range vals {
            cloned.Header.Add(k, v)
        }
    }
    return t.base.RoundTrip(cloned)
}
```

This correctly handles:
```bash
--header "Cookie: a=1" --header "Cookie: b=2"  # Both cookies sent
--header "Accept: application/json" --header "Accept: text/plain"  # Both values sent
```

**Scope:** Headers apply to: crawl requests, juicy file probes, cloud storage checks, GraphQL introspection. Does NOT apply to validation requests (separate client) or webhook sends.

### 3. `--scope-file` for Program Scopes

**Problem:** `--scope` takes a single regex. Bug bounty programs have multiple in-scope domains. Users paste scope lists into regex manually.

**Solution:** Load scope patterns from a file, combine with existing `--scope`.

**Flag:**
- `--scope-file` (string): Path to file with scope patterns
- Env var: `SYCK_SCAN_SCOPE_FILE`

**File format:**
```
# Bugcrowd scope for Example Corp
# One regex per line
app\.example\.com
api\.example\.com
.*\.staging\.example\.com
# Assets wildcard
cdn\.example\.com
```

**Parsing rules:**
- Lines starting with `#` → comments, skipped
- Empty/whitespace-only lines → skipped
- Each line treated as a **regex pattern** (consistent with `--scope`)
- Patterns compiled as **separate `*regexp.Regexp` objects** (not combined into one alternation regex) — better for debugging which scope matched, avoids regex engine backtracking on large alternations
- `--scope` and `--scope-file` patterns are checked in order; first match wins
- If only `--scope-file` provided (no `--scope`), only file patterns apply
- Error if file doesn't exist or contains no valid patterns

**Implementation:** Parse in `cmd/scan.go` before passing to `scanner.Config`. Add `ScopePatterns []*regexp.Regexp` to Config.

### 4. Robots.txt + Sitemap Discovery

**Problem:** Bug bounty hunters manually check robots.txt and sitemap.xml for hidden endpoints. SYCK's crawler already parses robots.txt for compliance but discards `Sitemap:` directives. No sitemap fetching at all.

**Solution:** Extend the existing `RobotsCache` to extract sitemap URLs, add sitemap XML parsing, and feed discovered URLs into the crawler queue.

**Discovery flow:**
```
For each domain visited during crawl:
  1. Fetch robots.txt (already done by RobotsCache)
  2. Extract Sitemap: directives (NEW)
  3. Proactively fetch /sitemap.xml and /sitemap_index.xml (NEW)
  4. Parse XML to extract <loc> URLs (NEW)
  5. Handle sitemap index files recursively (NEW)
  6. Feed all discovered URLs into crawler queue (NEW)
```

**Changes to `internal/crawler/robots.go`:**
- Add `Sitemaps []string` field to `robotsRule` struct
- Parse `Sitemap:` directives in `parseRobotsTxt()` (case-insensitive key)
- Add `Sitemaps(rawURL string) []string` method on `RobotsCache`
- Remove nil return for empty rules (a robots.txt with only Sitemap directives is still valid)

**New file `internal/crawler/sitemap.go`:**
```go
package crawler

const (
    MaxSitemapDepth       = 3     // Max recursion depth for sitemap index files
    MaxSitemapsPerDomain  = 100   // Max sitemap fetches per domain
    MaxURLsFromSitemaps   = 10000 // Max URLs extracted from sitemaps per domain
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

// FetchSitemaps fetches sitemap URLs for a domain.
// Tries: Sitemap directives from robots.txt, /sitemap.xml, /sitemap_index.xml
// Respects MaxSitemapDepth, MaxSitemapsPerDomain, MaxURLsFromSitemaps limits.
func (sf *SitemapFetcher) FetchSitemaps(domain string, robotsSitemaps []string) []string

// ParseSitemap parses a sitemap XML and returns URLs.
func ParseSitemap(content string) []SitemapURL

// ParseSitemapIndex parses a sitemap index and returns nested sitemap URLs.
func ParseSitemapIndex(content string) []string
```

**Recursion safety:**
- `MaxSitemapDepth = 3` — sitemap index → sitemap index → sitemap index (stops here)
- `MaxSitemapsPerDomain = 100` — prevents abuse from adversarial sitemaps
- `MaxURLsFromSitemaps = 10000` — caps memory usage per domain
- All limits tracked via a `sitemapState` struct passed through recursion

**Integration into crawler.go:**
- After `RobotsCache.getOrCreate(domain)`, call `SitemapFetcher.FetchSitemaps(domain, rule.Sitemaps)`
- **Scope filtering BEFORE enqueue:** Parse each discovered URL, check host against scope regex, then enqueue only in-scope URLs. This prevents huge sitemap files from consuming memory for out-of-scope assets.
- Deduplicate discovered URLs against already-visited set
- Add discovered URLs to crawl queue (subject to `CrawlLimit`)
- Log discovered sitemap URLs at debug level

**Sitemap URL processing flow:**
```
Fetch sitemap XML
→ Parse XML → extract <loc> URLs
→ For each URL:
    → Parse host
    → Check scope regex (early filter)
    → Check dedup (visited set)
    → Enqueue if in-scope + not visited
```

**CrawlConfig additions:**
```go
SitemapEnabled bool // default true, disable with --no-sitemap
```

**New flag:**
- `--no-sitemap` (bool): Disable sitemap discovery
- Env var: `SYCK_SCAN_NO_SITEMAP`

**Performance:** Sitemap parsing is lightweight (XML is small). The main cost is HTTP fetches, which are already rate-limited by the crawler's host semaphore. Max 3 sitemap fetches per domain (robots.txt sitemaps + /sitemap.xml + /sitemap_index.xml).

### 5. `--cookie` Flag

**Problem:** No way to inject specific session cookies for authenticated scanning. Cookie jar persists across runs but requires manual cookie management.

**Flag:**
- `--cookie` (string): Cookie string in `name=value; name2=value2` format (like browser cookie header)
- Env var: `SYCK_SCAN_COOKIE`

**Implementation:**
- Parse cookie string into `[]*http.Cookie` using a custom parser
- Go's `http.ParseCookie()` is designed for a single Set-Cookie header, not the `Cookie:` request header format (`name1=value1; name2=value2`). A small custom parser splitting on `; ` and parsing each `name=value` pair is more reliable.
- Add parsed cookies to the cookie jar before crawl starts
- Also injected via headerTransport alongside `--header` values (as `Cookie:` header)
- Compatible with `--cookie-file` (existing cookie jar persistence)
- **Must test** with edge cases: cookies with `=` in value, spaces around `; `, empty values, quoted values

### 6. Cloud Metadata Detection Rules

**Problem:** No detection of cloud metadata endpoints (critical SSRF/IMDSv1 attack vectors).

**Solution:** Add rules to `internal/rules/builtin.yaml`.

**New rules (3):**

```yaml
# AWS IMDS endpoint
- name: cloud_metadata_aws
  severity: high
  pattern: '169\.254\.169\.254(?:/latest/meta-data/|/latest/user-data/|/latest/dynamic/instance-identity/)'
  description: 'AWS EC2 Instance Metadata Service endpoint'
  tags: [cloud, aws, ssrf, metadata]

# GCP metadata endpoint
- name: cloud_metadata_gcp
  severity: high
  pattern: 'metadata\.google\.internal'
  description: 'GCP Compute Engine metadata endpoint'
  tags: [cloud, gcp, ssrf, metadata]

# Azure metadata endpoint
- name: cloud_metadata_azure
  severity: high
  pattern: '169\.254\.169\.254/metadata/instance'
  description: 'Azure Instance Metadata Service endpoint'
  tags: [cloud, azure, ssrf, metadata]
```

**Severity:** `high` (not critical). Finding a metadata URL in source code is informational — it indicates potential SSRF config but is not confirmed exploitation. A real critical finding would be the endpoint actually responding (future validation work).

**Rule properties:**
- No entropy threshold (exact match)
- No context keywords needed (the URL itself is the finding)
- Tags: cloud, provider, ssrf, metadata

### 7. `.env` File-Specific Rules

**Problem:** The `dotenv_secret` rule only catches a few patterns. Many provider-specific env vars are missed.

**Solution:** Add targeted rules for high-value env var patterns with FP reduction.

**New rules (6):**

```yaml
# Sensitive connection string env vars
- name: env_sensitive_var
  severity: high
  pattern: '(?:^|\s)(?:DATABASE_URL|REDIS_URL|MONGODB_URI|MONGODB_CONNECTION|MONGO_URI|SUPABASE_URL|SUPABASE_KEY|SUPABASE_SERVICE_KEY)=(.+)'
  description: 'Sensitive environment variable with connection string or URL'
  tags: [env, database, sensitive]

# Provider-specific token env vars
- name: env_token_var
  severity: high
  pattern: '(?:^|\s)(?:MAILGUN_API_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY|ALGOLIA_API_KEY|ALGOLIA_SEARCH_KEY|STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET|SQUARE_ACCESS_TOKEN)=(.+)'
  description: 'Provider-specific sensitive token in environment variable'
  tags: [env, token, provider]

# Generic secret env var (FP-reduced)
- name: env_generic_secret
  severity: medium
  pattern: '(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})'
  description: 'Generic secret/password/token environment variable'
  tags: [env, generic, secret]
  requires_context: true
  context_keywords: [secret, token, password, key, api, auth, access, private]
  entropy_threshold: 3.0
  # FP reductions applied:
  # 1. Minimum value lengths (8 for secret/password, 20 for token/api_key)
  # 2. requires_context: true — only fires on lines containing relevant keywords
  # 3. entropy_threshold: 3.0 — filters placeholder values

# .env file detection
- name: dotenv_file_secret
  severity: high
  pattern: '(?:^|\s)(?:SECRET|TOKEN|API_KEY|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|DATABASE_URL|REDIS_URL|MONGODB_URI)=(.+)'
  description: 'Sensitive value in .env or dotenv file'
  tags: [env, dotenv, secret]

# AWS env var patterns
- name: env_aws_secret
  severity: critical
  pattern: '(?:^|\s)AWS_SECRET_ACCESS_KEY=(?![\s]*$)(\S+)'
  description: 'AWS Secret Access Key in environment variable'
  tags: [env, aws, cloud]

# .npmrc auth token
- name: npmrc_auth_token
  severity: high
  pattern: '_authToken\s*=\s*(?:ghp_|npm_)?[A-Za-z0-9_-]{20,}'
  description: 'npm auth token in .npmrc file'
  tags: [env, npm, token]
```

**FP reduction in `env_generic_secret`:**
- Minimum value lengths prevent matching empty or short placeholder values
- `requires_context: true` with `context_keywords` ensures the line contains a relevant keyword (secret, token, password, etc.)
- `entropy_threshold: 3.0` filters low-entropy values like `changeme`, `test`, `xxx`

**Total new rules: 9** (3 metadata + 6 env)

### 8. `--diff` Mode

**Problem:** When re-scanning with cache, users see ALL findings including previously triaged ones. Need to see only NEW findings.

**Flag:**
- `--diff` (bool): Only output findings not previously seen
- Env var: `SYCK_SCAN_DIFF=true`
- **Requires `--cache-db`** — if `--diff` is set without `--cache-db`, return error: `"--diff requires --cache-db for cross-run comparison"`

**Implementation:**
- After all scanning and post-processing, filter findings by `IsNew == true`
- `IsNew` is already set by `RecordWithMeta` in the cache flow
- Diff filter runs AFTER severity filter, so `--diff --severity HIGH` shows only NEW HIGH+ findings
- Works with all 7 output formats (including jsonl)

**Filter position in pipeline:**
```
Scan → Dedup → FP Downgrade → SyckIgnore → Validate → Cache Record → Severity Filter → [DIFF FILTER] → Format → Output
```

**Edge cases:**
- `--diff` without `--cache-db` → error
- `--diff` with empty cache (first run) → all findings are "new"
- `--diff` with cache but no previous verdicts → same as no diff (all findings have IsNew=true from Record)

### 9. `--format jsonl` (JSON Lines / NDJSON)

**Problem:** JSON formatter accumulates all findings in memory then marshals. No streaming. Can't pipe to `jq` per-finding or stream to SIEM.

**Solution:** New `jsonl` format option.

**Flag value:** `--format jsonl`

**Output format:** One JSON object per line (NDJSON):
```json
{"file":"app.js","line":42,"rule":"aws_access_key","severity":"CRITICAL","secret":"AKIA...","entropy":4.2,"context":"aws_access_key = ...","confidence":75,"verification":"POTENTIAL","adaptive_modifier":0,"learning_tier":""}
{"file":"config.js","line":15,"rule":"github_pat","severity":"CRITICAL","secret":"ghp_...","entropy":4.5,"context":"token = ...","confidence":90,"verification":"VERIFIED","adaptive_modifier":3,"learning_tier":"Mature"}
```

**Properties:**
- One finding per line, no wrapping array
- No summary object (summary is a separate concern)
- Compatible with `jq` piping: `syck scan -f jsonl . | jq 'select(.severity == "CRITICAL")'`
- Compatible with `--output` flag for file output
- Compatible with `--webhook-url` (webhook receives the full JSON payload, not JSONL)
- Compatible with `--redact` and `--no-color`
- Includes adaptive_modifier and learning_tier fields (when non-zero)

**Implementation:** New `JSONLFormatter` in `internal/formatters/jsonl.go` implementing `Formatter` interface.

### 10. `--http-timeout` Flag

**Problem:** All HTTP timeouts hardcoded at 10s across 6+ locations. Can't adjust for slow targets or fast internal networks.

**Flag:**
- `--http-timeout` (duration): HTTP client timeout for all requests
- Default: `10s`
- Env var: `SYCK_SCAN_HTTP_TIMEOUT`
- Minimum: `1s` (clamp to prevent 0-timeout issues)

**Implementation:**
- Add `HTTPTimeout time.Duration` to `scanner.Config`
- The shared `httpclient.NewClient(timeout, proxy, insecure)` receives this value
- All 6 call sites use the config value instead of hardcoded `10 * time.Second`
- Upload SARIF keeps its 30s hardcoded (GitHub API is separate from scanning)
- Validator keeps 5s hardcoded (provider validation should be fast)

**Exception handling:** If `--http-timeout` is set, it overrides the scan/crawl/webhook clients. Validator and upload-sarif keep their own timeouts for reliability.

## File Changes Summary

| File | Changes |
|------|---------|
| `internal/httpclient/client.go` | **NEW** — `NewTransport()`, `NewClient()` |
| `internal/httpclient/client_test.go` | **NEW** — Tests for factory |
| `internal/crawler/robots.go` | Parse `Sitemap:` directives, add `Sitemaps()` method |
| `internal/crawler/sitemap.go` | **NEW** — `SitemapFetcher`, `ParseSitemap()`, `ParseSitemapIndex()` |
| `internal/crawler/sitemap_test.go` | **NEW** — Sitemap parsing tests |
| `internal/crawler/crawler.go` | Integrate sitemap discovery into BFS, add CrawlConfig fields |
| `internal/rules/builtin.yaml` | +9 new rules (3 metadata + 6 env) |
| `internal/scanner/scanner.go` | +4 fields: `HTTPTimeout`, `ProxyURL`, `Headers map[string][]string`, `ScopePatterns []*regexp.Regexp` |
| `internal/scanner/scan.go` | Use shared client factory, add diff filter, header injection |
| `internal/formatters/jsonl.go` | **NEW** — JSONL formatter |
| `internal/formatters/formatter.go` | Register `jsonl` in factory |
| `cmd/scan.go` | Add 7 new flags, scope-file parsing, diff validation, cookie parsing |
| `cmd/env.go` | Add 7 new env var bindings |
| `crawler/juicy.go` | Use injected client instead of local creation |
| `formatters/webhook.go` | Accept proxyURL via FormatOptions |
| `validator/http.go` | Accept shared transport |
| `cmd/upload_sarif.go` | Accept proxyURL from flags |

## CLI Flags Summary

| Flag | Type | Default | Env Var | Description |
|------|------|---------|---------|-------------|
| `--proxy` | string | `""` | `SYCK_SCAN_PROXY` | HTTP proxy URL for all requests |
| `--auth-token` | string | `""` | `SYCK_SCAN_AUTH_TOKEN` | Bearer token for crawl requests |
| `--header` | string (repeatable) | | `SYCK_SCAN_HEADER` | Custom header `Name: Value` |
| `--scope-file` | string | `""` | `SYCK_SCAN_SCOPE_FILE` | File with scope regex patterns |
| `--cookie` | string | `""` | `SYCK_SCAN_COOKIE` | Cookie string `name=value; name2=value2` |
| `--no-sitemap` | bool | `false` | `SYCK_SCAN_NO_SITEMAP` | Disable sitemap discovery |
| `--diff` | bool | `false` | `SYCK_SCAN_DIFF` | Only show new findings (requires --cache-db) |
| `--http-timeout` | duration | `10s` | `SYCK_SCAN_HTTP_TIMEOUT` | HTTP client timeout |

## Testing Strategy

- **Unit tests:** httpclient factory (transport creation, proxy, TLS), JSONL formatter, scope-file parsing, sitemap XML parsing, diff filter logic, cookie parsing
- **Integration tests:** End-to-end scan with proxy flag, scan with scope-file, diff mode with cache, JSONL piping to jq, sitemap discovery against mock server
- **Existing tests:** All 22 packages must continue to pass `go test -race ./...`

## Version & Release

- Version: V1.5.0
- Tag: v1.5.0
- GoReleaser: same targets (linux/darwin/windows x amd64/arm64)
- Breaking changes: none (all additions, no removals)
- Migration: none (new SQLite tables use IF NOT EXISTS, schema migration in OpenCache)

## Future V2 Features (Out of Scope)

- **JavaScript endpoint extraction from bundled JS** — extract `/api/v1/users`, `/graphql`, `/admin` from downloaded JS files (highest bug bounty ROI)
- GraphQL deeper schema crawling (mutation input discovery)
- Wayback Machine integration (waybackurls-style historical URL discovery)
- Passive subdomain ingestion (import from subfinder/amass/httpx)
- Response body fingerprinting (framework/CMS detection from HTML patterns)
- Expanded secret validation pipeline (more providers, JWT structural validation)
- Hidden parameter discovery (parameter brute-force, common param lists)
- CORS misconfiguration detection
- CSP/security header analysis
- Technology/framework fingerprinting (Wappalyzer-style)
- WAF detection from response headers
- **Metadata rule context boosting** — boost `cloud_metadata_*` findings when context includes `fetch`, `axios`, `curl`, `request`, `proxy` keywords (reduces FP on static IP lists like `blockedIPs`)
