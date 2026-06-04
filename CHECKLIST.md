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
- [x] --format (text/json)
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
- [ ] --git-history
- [ ] --fail-on (CI gate)
- [ ] --pipe (scan from stdin)
- [ ] --progress (TUI progress bar)
- [ ] --ignore-file (.syckignore)

## Output Formatters
- [x] Text (colorized terminal)
- [x] JSON
- [ ] SARIF 2.1.0
- [ ] Markdown
- [ ] CSV
- [ ] HTML (dark-themed)

## Post-Processing Pipeline
- [x] Deduplication
- [ ] FP downgrade (test/mock/vendor dirs, placeholder patterns)
- [ ] .syckignore fingerprint support
- [ ] Live secret validation (--validate)
- [ ] Webhook dispatch (--webhook-url)
- [ ] SARIF upload to GitHub Code Scanning

## Finding Struct
- [x] File, Line, Column, RuleName, Severity, Secret, Context, Entropy
- [ ] ContextBefore field
- [ ] ContextAfter field

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
