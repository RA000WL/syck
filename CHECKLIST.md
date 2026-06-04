# Go syck — Build Checklist

## Core Scanner
- [x] File walk with parallel workers
- [x] Text file detection (extension + content sniff)
- [x] Path exclusion via regex
- [x] Max file size filter
- [x] Skip dirs (.git, node_modules, etc.)
- [x] Streaming mode for >1MB files
- [x] Gzip/zlib decompression before scanning

## Detection Pipeline
- [x] Line-by-line regex matching against all rules
- [x] Entropy filter (Shannon, floor 2.0)
- [x] Entropy token scan (32+ char tokens, secret-context keywords)
- [x] Base64 decode + rescan
- [x] Hex decode + rescan
- [x] Unicode escape decode + rescan
- [x] URL-encoded decode + rescan
- [x] Recursive multi-layer decode (depth 4)
- [x] JSON-aware scan (walk parsed tree, check under known keys)
- [x] JS string reconstruction (concat/join/templates)
- [ ] Endpoint extraction (API/GraphQL/WebSocket URLs)
- [ ] Git history scanning

## Rules
- [x] 130 embedded YAML rules (precision-hardened, zero false-positive patterns)
- [x] Custom rules file override (--rules)
- [x] Port missing rules (vault_approle_id/secret, docker_hub_password, papertrail_api_token)
- [x] Fix kubernetes_secret case-insensitive flag
- [x] Remove 37 overly-generic rules (matched ANY string of N+ chars)
- [x] Add context anchors to 15 rules (datadog, okta, circleci, etc.)
- [x] Add Vercel prefixed tokens (vcp/vci/vca/vcr/vck)
- [x] Add modern AI providers (Together AI, Tavily, LangSmith)
- [x] Add Neon database provider

## CLI Flags
- [x] --severity
- [x] --format (text/json/sarif)
- [x] --output (-o file)
- [x] --redact
- [x] --no-dedup
- [x] --exclude (path regex)
- [x] --workers
- [x] --max-file-size
- [x] --config
- [x] --no-color
- [x] --debug
- [x] --quiet
- [x] --list-rules
- [x] --decode-base64 / --no-decode-base64
- [x] --decode-hex / --no-decode-hex
- [x] --decode-unicode / --no-decode-unicode
- [x] --decode-url / --no-decode-url
- [x] --decode-gzip
- [x] --js-reconstruct
- [x] --endpoints (flag wired, feature not implemented)
- [x] --pipe (scan from stdin)
- [x] --fail-on (CI gate: exit 1 if findings meet severity threshold)
- [x] --downgrade-fp (auto-downgrade test/mock/vendor findings)
- [x] --url / -u (URL to scan, can be repeated)
- [x] --url-file / -l (file containing URLs)
- [x] --scope (regex to filter crawled URLs)
- [x] --crawl-limit (max URLs to crawl, default 100)
- [x] --crawl-depth (max link follow depth, default 3)
- [x] --headless (headless Chrome for SPA/JS-rendered pages via go-rod)
- [x] --rate-limit (per-host request rate limiting with backoff)
- [x] --cookies (enable cookie jar for session handling, default: true)
- [x] --cookie-file (persist cookies to file between runs)
- [x] --concurrency (max concurrent fetches, default 10)
- [x] --host-concurrency (max concurrent fetches per host, default 2)
- [x] --ignore-robots (skip robots.txt Disallow rules)
- [ ] --git-history
- [ ] --progress (TUI progress bar)
- [ ] --ignore-file (.syckignore)

## Output Formatters
- [x] Text (colorized terminal)
- [x] JSON
- [x] SARIF 2.1.0
- [ ] Markdown
- [ ] CSV
- [ ] HTML (dark-themed)

## Post-Processing Pipeline
- [x] Deduplication
- [x] FP downgrade (test/mock/vendor dirs, placeholder patterns)
- [ ] .syckignore fingerprint support
- [ ] Live secret validation (--validate)
- [ ] Webhook dispatch (--webhook-url)
- [ ] SARIF upload to GitHub Code Scanning

## Finding Struct
- [x] File, Line, Column, RuleName, Severity, Secret, Context, Entropy
- [x] ContextBefore field
- [x] ContextAfter field

## URL Scanning
- [x] goquery-based HTML extraction (25+ tag types: a, link, script, img, iframe, frame, embed, object, video, audio, source, svg, table, button, blockquote, input, area, base, meta, htmx)
- [x] JS import/require regex extraction
- [x] Headless Chrome support via go-rod (SPA/JS-rendered pages)
- [x] Per-host rate limiting with configurable RPS
- [x] Random user-agent rotation (9 generators, 80+ real browser strings)
- [x] Cookie/session handling with optional file persistence
- [x] Parallel fetching with worker pool (configurable concurrency)
- [x] Per-host concurrency limits (avoid hammering one server)
- [x] HTTP client with gzip support and redirect limits
- [x] Scope filtering (regex-based domain/path filtering)
- [x] Crawl limits (max URLs + max depth)
- [x] Crawler with queue, visited set, and BFS traversal
- [x] ScanURLs integration (fetch → scan content → dedup)

## Crawler Features
- [x] Cookie/session handling (net/http/cookiejar + JSON persistence)
- [x] Parallel fetching with worker pool
- [x] Per-host concurrency limits (semaphore per hostname)
- [x] Clean Crawler struct refactor (stateful, holds jar/semaphores)
- [x] Robots.txt support (Phase 2)
- [x] Encoding detection + auto-conversion (Phase 2)
- [ ] SQLite URL cache across runs (Phase 3)
- [ ] Env var config (SYCK_*) (Phase 3)

## Documentation / Infra
- [x] Module path: github.com/RA000WL/syck
- [x] GitHub repo created
- [ ] README with usage examples
- [ ] CI workflow for Go build/tests
- [ ] Release binaries

## Benchmark Parity
- [x] Rules precision hardening complete (37 rules removed, 8 added)
- [x] Go: 17 correct-rule matches, 0 wrong-rule, 17 total findings (100% precision)
- [x] Python: 16 correct-rule matches, 119 wrong-rule, 135 total findings (11.9% precision)
- [x] Go now has BETTER precision than Python and more correct-rule matches
- [ ] Match Python's 36/39 file coverage (Go: 17/39, Python: 36/39)
- [ ] Remaining gap: 22 files missed due to test tokens shorter than pattern minimums
