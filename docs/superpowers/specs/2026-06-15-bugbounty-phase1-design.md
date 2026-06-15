# Phase 1: Bug Bounty Core — V1.5 Design Spec

> **Version:** 1.1 (updated with gap analysis findings)
> **Date:** 2026-06-15

## Overview

Phase 1 of making SYCK a professional bug bounty tool. Ships 8 components in a single release: proxy support, authenticated crawling, scope file loading, cloud metadata detection, .env rules, diff mode, JSONL output, and configurable HTTP timeouts.

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

**Dead code cleanup:** Remove `defaultHTTPClient` var at `crawler.go:92` (never used).

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
- Add `Headers map[string]string` to `scanner.Config`
- In `ScanURLs`, inject headers into HTTP requests via a custom `RoundTripper` wrapper OR by setting headers on each request
- The crawler's `Crawl()` method already uses `http.Request` — headers are set before each `Do()` call
- Headers apply to: crawl requests, juicy file probes, cloud storage checks, GraphQL introspection

**RoundTripper approach (cleanest):**
```go
type headerTransport struct {
    base    http.RoundTripper
    headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    for k, v := range t.headers {
        req.Header.Set(k, v)
    }
    return t.base.RoundTrip(req)
}
```

Wrap the shared transport with this before passing to the crawler client.

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
- Patterns combined with existing `--scope` into one alternation regex: `scope_regex|file_pattern1|file_pattern2|...`
- If only `--scope-file` provided (no `--scope`), the combined regex is just the file patterns
- Error if file doesn't exist or contains no valid patterns

**Implementation:** Parse in `cmd/scan.go` before passing to `scanner.Config`. The `Scope` field on Config becomes the combined regex.

### 4. Cloud Metadata Detection Rules

**Problem:** No detection of cloud metadata endpoints (critical SSRF/IMDSv1 attack vectors).

**Solution:** Add rules to `internal/rules/builtin.yaml`.

**New rules (3):**

```yaml
# AWS IMDS endpoint
- name: cloud_metadata_aws
  severity: critical
  pattern: '169\.254\.169\.254(?:/latest/meta-data/|/latest/user-data/|/latest/dynamic/instance-identity/)'
  description: 'AWS EC2 Instance Metadata Service endpoint'
  tags: [cloud, aws, ssrf, metadata]

# GCP metadata endpoint
- name: cloud_metadata_gcp
  severity: critical
  pattern: 'metadata\.google\.internal'
  description: 'GCP Compute Engine metadata endpoint'
  tags: [cloud, gcp, ssrf, metadata]

# Azure metadata endpoint
- name: cloud_metadata_azure
  severity: critical
  pattern: '169\.254\.169\.254/metadata/instance'
  description: 'Azure Instance Metadata Service endpoint'
  tags: [cloud, azure, ssrf, metadata]
```

**Rule properties:**
- Severity: critical (these are always high-value findings)
- No entropy threshold (exact match)
- No context keywords needed (the URL itself is the finding)
- Tags: cloud, provider, ssrf, metadata

### 5. `.env` File-Specific Rules

**Problem:** The `dotenv_secret` rule only catches a few patterns. Many provider-specific env vars are missed.

**Solution:** Add targeted rules for high-value env var patterns.

**New rules (6):**

```yaml
# Generic sensitive env var pattern
- name: env_sensitive_var
  severity: high
  pattern: '(?:^|\s)(?:DATABASE_URL|REDIS_URL|MONGODB_URI|MONGODB_CONNECTION|MONGO_URI|SUPABASE_URL|SUPABASE_KEY|SUPABASE_SERVICE_KEY)=(.+)'
  description: 'Sensitive environment variable with connection string or URL'
  tags: [env, database, sensitive]

# Generic token/key env var pattern
- name: env_token_var
  severity: high
  pattern: '(?:^|\s)(?:MAILGUN_API_KEY|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY|ALGOLIA_API_KEY|ALGOLIA_SEARCH_KEY|STRIPE_SECRET_KEY|STRIPE_LIVE_SECRET|SQUARE_ACCESS_TOKEN|SQUARE_LOCATION_ID)=(.+)'
  description: 'Provider-specific sensitive token in environment variable'
  tags: [env, token, provider]

# Generic password/secret env var (catch-all)
- name: env_generic_secret
  severity: medium
  pattern: '(?:^|\s)(?:\w+_SECRET=\S+|\w+_PASSWORD=\S+|\w+_TOKEN=\S+|\w+_KEY=\S+)'
  description: 'Generic secret/password/token environment variable'
  tags: [env, generic, secret]
  requires_context: true
  context_keywords: [secret, token, password, key]
  entropy_threshold: 3.0

# .env file detection boost
- name: dotenv_file_secret
  severity: high
  pattern: '(?:^|\s)(?:SECRET|TOKEN|API_KEY|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|DATABASE_URL|REDIS_URL|MONGODB_URI)=(.+)'
  description: 'Sensitive value in .env or dotenv file'
  tags: [env, dotenv, secret]
  # Note: This rule fires more aggressively when the file is a .env file (detected by extension)

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

**Total new rules: 6** (bringing total to ~170)

### 6. `--diff` Mode

**Problem:** When re-scanning with cache, users see ALL findings including previously triaged ones. Need to see only NEW findings.

**Flag:**
- `--diff` (bool): Only output findings not previously seen
- Env var: `SYCK_SCAN_DIFF=true`
- **Requires `--cache-db`** — if `--diff` is set without `--cache-db`, return error: `"--diff requires --cache-db for cross-run comparison"`

**Implementation:**
- After all scanning and post-processing (dedup, downgrade, ignore), filter findings by `IsNew == true`
- `IsNew` is already set by `RecordWithMeta` in the cache flow
- Filter runs after severity filtering so `--diff --severity HIGH` shows only NEW HIGH+ findings
- Works with all 6 output formats

**Filter position in pipeline:**
```
Scan → Dedup → FP Downgrade → SyckIgnore → Validate → Cache Record → [DIFF FILTER] → Severity Filter → Format → Output
```

**Edge cases:**
- `--diff` without `--cache-db` → error
- `--diff` with empty cache (first run) → all findings are "new"
- `--diff` with cache but no previous verdicts → same as no diff (all findings have IsNew=true from Record)

### 7. `--format jsonl` (JSON Lines / NDJSON)

**Problem:** JSON formatter accumulates all findings in memory then marshals. No streaming. Can't pipe to `jq` per-finding or stream to SIEM.

**Solution:** New `jsonl` format option.

**Flag value:** `--format jsonl`

**Output format:** One JSON object per line (NDJSON):
```
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

**Implementation:** New `JSONLFormatter` in `internal/formatters/jsonl.go` implementing `Formatter` interface.

### 8. `--http-timeout` Flag

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
| `internal/rules/builtin.yaml` | +9 new rules (3 metadata + 6 env) |
| `internal/scanner/scanner.go` | +2 fields: `HTTPTimeout`, `ProxyURL`, `Headers`, `ScopeFile` |
| `internal/scanner/scan.go` | Use shared client factory, add diff filter, header injection |
| `internal/formatters/jsonl.go` | **NEW** — JSONL formatter |
| `internal/formatters/formatter.go` | Register `jsonl` in factory |
| `cmd/scan.go` | Add 6 new flags, scope-file parsing, diff validation |
| `cmd/env.go` | Add 6 new env var bindings |
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
| `--diff` | bool | `false` | `SYCK_SCAN_DIFF` | Only show new findings (requires --cache-db) |
| `--http-timeout` | duration | `10s` | `SYCK_SCAN_HTTP_TIMEOUT` | HTTP client timeout |

## Testing Strategy

- **Unit tests:** httpclient factory (transport creation, proxy, TLS), JSONL formatter, scope-file parsing, diff filter logic
- **Integration tests:** End-to-end scan with proxy flag, scan with scope-file, diff mode with cache, JSONL piping to jq
- **Existing tests:** All 22 packages must continue to pass `go test -race ./...`

## Version & Release

- Version: V1.5.0
- Tag: v1.5.0
- GoReleaser: same targets (linux/darwin/windows x amd64/arm64)
- Breaking changes: none (all additions, no removals)
- Migration: none (new SQLite tables use IF NOT EXISTS, schema migration in OpenCache)
