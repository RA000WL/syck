# Go syck — Build Checklist

## Core Scanner
- [x] File walk with parallel workers
- [x] Text file detection (extension + content sniff)
- [x] Path exclusion via regex
- [x] Max file size filter
- [x] Skip dirs (.git, node_modules, etc.)
- [ ] Streaming mode for >1MB files
- [ ] Gzip/zlib decompression before scanning

## Detection Pipeline
- [x] Line-by-line regex matching against all rules
- [x] Entropy filter (Shannon, floor 2.0)
- [x] Entropy token scan (32+ char tokens, secret-context keywords)
- [x] Base64 decode + rescan
- [x] Hex decode + rescan
- [x] Unicode escape decode + rescan
- [x] URL-encoded decode + rescan
- [x] Recursive multi-layer decode (depth 4)
- [ ] JSON-aware scan (walk parsed tree, check under known keys)
- [x] JS string reconstruction (concat/join/templates)
- [ ] Endpoint extraction (API/GraphQL/WebSocket URLs)
- [ ] Git history scanning

## Rules
- [x] 162 embedded YAML rules
- [x] Custom rules file override (--rules)
- [ ] Port remaining ~18 missing rules (Python has 180)
- [ ] Fix ~17 RE2-incompatible patterns (lookahead/lookbehind)

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
- [ ] --decode-base64 / --no-decode-base64
- [ ] --decode-hex / --no-decode-hex
- [ ] --decode-unicode / --no-decode-unicode
- [ ] --decode-url / --no-decode-url
- [ ] --decode-gzip
- [ ] --js-reconstruct
- [ ] --endpoints
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
- [ ] Match Python: 160 findings across 39 files
- [ ] Current: 153 findings across 38 files
- [ ] Delta: 7 missing (18 missing rules, no entropy token scan, no JSON scan)
