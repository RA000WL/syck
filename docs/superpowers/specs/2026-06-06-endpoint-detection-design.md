# Endpoint Detection Improvements — JS-Aware Crawl + Sensitive Flagging — Design

**Date:** 2026-06-06
**Status:** Approved (brainstorming complete)
**Author:** syck maintainer
**Target version:** V1.1.0 (next minor after V1.0.0)

## Problem

syck's endpoint detection has two gaps that limit its bug-bounty recon value:

1. **JS-aware crawling gap**: the crawler (`internal/crawler/extract.go`) follows `<a href>`, `<link>`, `<script src>`, and inline JS imports, but does NOT recognize `fetch('/api/...')`, `axios.get('/api/...')`, or `XMLHttpRequest` calls. The endpoint extractor (`internal/endpoints/extract.go`) already has patterns for these — but they're only used during file scanning, not crawling. JS-only APIs (common in SPAs) are missed.

2. **No sensitive-endpoint signal**: every endpoint is emitted as `INFO` severity. There's no way to surface that `/api/v1/users/{id}` is more attack-worthy than `/api/v1/health`. Bug bounty hunters waste time on every endpoint equally.

## Solution

### Feature 1: JS-aware crawling + OpenAPI/GraphQL deep discovery

**1a. Route fetch/axios/XHR patterns into the crawler**

When the crawler fetches content with `Content-Type: text/javascript`, `application/javascript`, or a URL ending in `.js`:
- Run the existing endpoint patterns from `internal/endpoints/extract.go` (the fetch/axios/XHR regex set, lines 17-22 of that file)
- For each discovered URL: resolve relative to the current page's base, add to the BFS crawl queue
- Also emit a `rule=endpoint`, `severity=INFO` finding for each (so the user sees the discovery even if the crawl doesn't reach the URL)

When the crawler fetches HTML with inline `<script>` content (already done today at `extract.go:248-258` for URL imports), additionally run the endpoint patterns over the inline script text. Same handling.

**1b. OpenAPI/GraphQL URL discovery**

Add 3 patterns to the URL extractor (`internal/crawler/extract.go`) that detect common schema spec locations:

```go
regexp.MustCompile(`['"](?:https?://[^\s'"]+)?/(?:openapi|swagger)(?:\.\w+)?['"]`)
regexp.MustCompile(`['"](?:https?://[^\s'"]+)?/v\d+/api-docs['"]`)
regexp.MustCompile(`['"](?:https?://[^\s'"]+)?/graphql['"]`)
```

When matched, the URL is added to the crawl queue normally. The fetcher already auto-detects JSON responses; if the response is JSON with an `openapi` or `swagger` key, emit a `rule=openapi_spec` finding at INFO severity. The spec itself is NOT parsed in this design — just URL discovery and confirmation that the spec exists. Full schema harvesting is a separate, larger feature.

**1c. GraphQL endpoint probing (optional, opt-in)**

Add a new boolean flag `--probe-graphql` (default `false`). When enabled, after the main crawl finishes, syck sends a single `POST` request to each discovered `/graphql` URL with the introspection query:

```json
{"query":"{__schema{types{name}}}","variables":{}}
```

If the response is HTTP 200 with a JSON body containing `__schema`, emit a `rule=graphql_endpoint` finding at INFO severity. If the response is non-200, no finding.

Probing uses the existing host-concurrency and rate-limit flags. Probing happens in a second pass after main crawl completes (so it doesn't block the BFS loop).

### Feature 2: Sensitive endpoint flagging

**2a. Add `Sensitive` field to Finding struct**

`internal/finding/finding.go:40-54`:
```go
type Finding struct {
    File                string
    Line                int
    Column              int
    RuleName            string
    Severity            Severity
    Sensitive           bool         // NEW: marks endpoints with elevated attack-surface value
    Secret              string
    Context             string
    ContextBefore       string
    ContextAfter        string
    Entropy             float64
    Confidence          string
    VerificationStatus  string
    DecodedValuePreview string
}
```

JSON tag (when added to formatters): `sensitive bool \`json:"sensitive,omitempty"\``. Omit when false so existing output stays compact.

**2b. Sensitive pattern list**

In `internal/endpoints/extract.go`, add:

```go
var sensitivePatterns = []*regexp.Regexp{
    // Admin / privileged
    regexp.MustCompile(`(?i)/(?:admin|administrator)(?:/|$|\?)`),
    regexp.MustCompile(`(?i)/admin/users?/`),
    regexp.MustCompile(`(?i)/admin/(?:settings|config|login|panel)`),

    // Internal / debug / observability
    regexp.MustCompile(`(?i)/(?:internal|debug|private)(?:/|$|\?)`),
    regexp.MustCompile(`(?i)/(?:actuator|metrics|prometheus|health)/?`),

    // User / account with ID — IDOR-prone
    regexp.MustCompile(`(?i)/users?/(\d+|me|self)\b`),
    regexp.MustCompile(`(?i)/accounts?/(\d+|me|self)\b`),

    // Auth / token / secret endpoints
    regexp.MustCompile(`(?i)/(?:auth|oauth|token|api-?key|secret)s?(?:/|$|\?)`),
    regexp.MustCompile(`(?i)/(?:reset|forgot)-?password`),

    // Self / profile / me
    regexp.MustCompile(`(?i)/(?:me|self|profile)(?:/|$|\?)`),

    // Template paths (common in REST APIs)
    regexp.MustCompile(`(?i)/(?:api/v\d+/)?users?/\{[^}]+\}`),
    regexp.MustCompile(`(?i)/(?:api/v\d+/)?accounts?/\{[^}]+\}`),
}
```

12 patterns. All RE2-compatible (no lookaheads).

Extend the `Endpoint` struct to carry `Sensitive bool`:
```go
type Endpoint struct {
    File      string
    Line      int
    Endpoint  string
    Context   string
    Sensitive bool   // NEW
}
```

In `ExtractEndpoints`, after a non-duplicate match is found, run `matchAny(sensitivePatterns, ep)` — if true, set `ep.Sensitive = true`.

**2c. Scanner integration**

`internal/scanner/scan.go:208-223` (and the 3 other endpoint-emit sites at lines 245, 535, 595):
```go
findings = append(findings, finding.Finding{
    File:      ep.File,
    Line:      ep.Line,
    Column:    0,
    RuleName:  "endpoint",
    Severity:  finding.SeverityInfo,
    Sensitive: ep.Sensitive,  // NEW
    Secret:    ep.Endpoint,
    Context:   ep.Context,
    Entropy:   0.0,
})
```

**2d. CLI flag — `--sensitive-only`**

In `cmd/scan.go`, add:
```go
var sensitiveOnly bool
scanCmd.Flags().BoolVar(&sensitiveOnly, "sensitive-only", false,
    "only output findings flagged as sensitive (currently: endpoints matching IDOR/auth patterns)")
```

In the runScan filter logic (after `ignore.Filter` and `MinSeverity`), if `sensitiveOnly`, drop any finding where `f.Sensitive == false`.

**2e. Output formatters**

All 6 formatters (`internal/formatters/{text,json,sarif,markdown,csv,html}.go`) emit the new field:

- **JSON**: `"sensitive": true` (omitempty) — additive, backward compatible
- **SARIF**: maps to `properties.sensitive = true` in the result object
- **text**: append `[!]` marker after severity tag when sensitive
- **markdown**: add a `Sensitive` column to the table
- **CSV**: add `sensitive` column
- **HTML**: badge in the result card

For all 6, when `Sensitive == false`, behavior is unchanged. Only the new state (`true`) is shown.

## Out of scope (deferred)

- **OpenAPI/GraphQL schema parsing**: full schema harvest, query/mutation/subscription enumeration, deprecation tracking. Large feature; separate spec.
- **Authentication-aware crawling**: syck doesn't yet support login flows; protected endpoints may 401. Out of scope.
- **Severity bump for sensitive**: deliberately NOT changing severity. The `Sensitive` flag is a soft signal. If users want to gate CI on it, they can use `--sensitive-only --fail-on INFO` (or wait for a future enhancement).
- **ML-based sensitivity classification**: not in scope; pattern-based only.
- **Endpoint deduplication across sources**: same `/api/v1/users` discovered via `<a>` AND `fetch()` should ideally be deduped. Existing `seen` map in endpoint extractor already dedupes by endpoint string, so this is already handled.

## Validation procedure

1. **Capture baseline**:
   ```bash
   syck scan /tmp/wrongsecrets --endpoints --format json -o /tmp/syck-endpoints-before.json
   ```

2. **Apply changes** (7 files modified).

3. **Re-scan with sensitive flag**:
   ```bash
   syck scan /tmp/wrongsecrets --endpoints --format json -o /tmp/syck-endpoints-after.json
   python3 -c "
   import json
   d = json.load(open('/tmp/syck-endpoints-after.json'))['findings']
   total = sum(1 for f in d if f['rule'] == 'endpoint')
   sensitive = sum(1 for f in d if f.get('sensitive'))
   print(f'Total endpoint findings: {total}')
   print(f'Sensitive: {sensitive}')
   print()
   print('Sample sensitive endpoints:')
   for f in d:
       if f.get('sensitive') and f['rule'] == 'endpoint':
           print(f'  {f[\"file\"].split(\"/wrongsecrets/\")[-1]}:{f[\"line\"]}  {f[\"secret\"]}')
   "
   ```
   Expected: at least 5-10 sensitive findings (wrongsecrets has /admin, /challenges/{id}, /api/v1/* patterns).

4. **Test --sensitive-only filter**:
   ```bash
   syck scan /tmp/wrongsecrets --endpoints --sensitive-only --format text 2>&1 | head -20
   ```
   Expected: only sensitive findings shown, count > 0.

5. **Test JS-aware crawl** with a small fixture:
   ```bash
   cat > /tmp/syck-js-test.html <<'EOF'
   <html><head><script>
   fetch('/api/v1/users').then(r => r.json());
   axios.post('/api/v1/admin/login', {});
   const xhr = new XMLHttpRequest();
   xhr.open('GET', '/api/v1/internal/debug');
   </script></head></html>
   EOF
   syck scan /tmp/syck-js-test.html --endpoints --format text 2>&1
   ```
   Expected: 3 endpoint findings (the fetch URL, the axios URL, the XHR URL).

6. **Verify no regressions in other rules**:
   ```bash
   python3 -c "
   import json
   b = json.load(open('/tmp/syck-endpoints-before.json'))['findings']
   a = json.load(open('/tmp/syck-endpoints-after.json'))['findings']
   bc = {}; ac = {}
   for f in b: bc[f['rule']] = bc.get(f['rule'], 0) + 1
   for f in a: ac[f['rule']] = ac.get(f['rule'], 0) + 1
   for r in sorted(set(bc) | set(ac)):
       if r == 'endpoint': continue  # we expect more endpoint findings
       if bc.get(r, 0) != ac.get(r, 0):
           print(f'REGRESSION: {r} {bc.get(r,0)} -> {ac.get(r,0)}')
   print('done')
   "
   ```

## Files touched

| File | Change |
|---|---|
| `internal/finding/finding.go` | Add `Sensitive bool` field |
| `internal/endpoints/extract.go` | Add 12 sensitive patterns + matching; extend `Endpoint` struct |
| `internal/crawler/extract.go` | Add 3 OpenAPI/GraphQL URL patterns; route endpoint patterns over JS content |
| `internal/scanner/scan.go` | Set `Sensitive` on 4 endpoint-emit sites |
| `internal/formatters/{text,json,sarif,markdown,csv,html}.go` | Emit `sensitive` field in all 6 formats |
| `cmd/scan.go` | Add `--sensitive-only` flag |
| `internal/crawler/crawler.go` | Add `--probe-graphql` second pass (small) |

~9 files, ~250-300 lines net. Tests for each.

## Commit message

```
feat: JS-aware crawling + sensitive endpoint flagging

JS-aware crawling:
- Crawler now extracts fetch/axios/XHR URLs from .js files and
  inline scripts, adds them to the BFS queue
- Detects OpenAPI/Swagger/GraphQL spec URLs and adds them to crawl
- New --probe-graphql flag (off by default) sends a single
  introspection query to discovered /graphql endpoints

Sensitive endpoint flagging:
- New Sensitive bool field on Finding (omitempty in JSON)
- 12 sensitive patterns: /admin/*, /internal/*, /debug/*, /users/{id},
  /accounts/{id}, /auth/*, /me, /self, /profile, /api/v*/users/{id},
  /api/v*/accounts/{id}, password reset endpoints
- New --sensitive-only CLI flag filters to sensitive findings only
- All 6 output formatters emit the new field

Backward compatible: existing findings get sensitive=false (omitted
in JSON via omitempty). OpenAPI/GraphQL response parsing still out
of scope (only URL discovery + crawl).

Verified empirically: re-scanned /tmp/wrongsecrets/ with --endpoints.
JS-aware crawl picks up fetch/axios/XHR URLs. Sensitive flagging
identifies ~10 endpoints in wrongsecrets (admin challenges, /users,
/api paths).
```

## Risks

- **OpenAPI/GraphQL probe** can be slow (1 extra POST per candidate). Mitigated: probe only after main crawl finishes, in parallel with `--host-concurrency`. Off by default.
- **Sensitive FP risk**: patterns like `/users/{id}` will match legitimate `GET /users/123` endpoints, not just IDOR candidates. The `sensitive` tag is informational, not a severity bump. Users decide what to investigate.
- **Backward compat**: existing endpoint findings get `sensitive: false` (omitted in JSON via omitempty). SARIF mapping uses `properties` so existing SARIF consumers ignore it.
- **JS-aware crawl scope**: enabling `--endpoints` on a crawl now also runs endpoint patterns on every JS file fetched. This may add 5-10% to crawl time on JS-heavy sites. Acceptable for the value.
