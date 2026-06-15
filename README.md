# SYCK(SecretsYouCantKeep)

[![CI](https://github.com/RA000WL/syck/actions/workflows/ci.yml/badge.svg)](https://github.com/RA000WL/syck/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RA000WL/syck)](https://github.com/RA000WL/syck/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)

A fast, modular secret scanner written in Go. 160+ detection rules, multi-layer decoding, entropy analysis, URL crawling, and live secret validation — all in a single static binary.

**Why syck?** Most secret scanners either miss too much (regex-only) or drown you in false positives (entropy-only). syck combines both with rule-specific context keywords, decoder layers, confidence scoring, and a precision-hardened rule set.

## Features

- **160+ detection rules** — AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, SendGrid, email/password hashes, PII, and 50+ providers
- **Entropy analysis** — Shannon entropy scoring with per-alphabet thresholds and media token filtering
- **Confidence scoring** — numeric 0-100 confidence with LOW/MEDIUM/HIGH/CRITICAL bands and detection method tags
- **Contextual entropy** — keyword-gated entropy detection finds secrets even without specific rule matches
- **6 output formats** — text, JSON, SARIF 2.1.0, Markdown, CSV, dark-themed HTML
- **URL crawling** — BFS crawler with goquery HTML extraction, per-host rate limiting, scope filtering
- **Headless Chrome** — SPA/JS-rendered page support via go-rod
- **Git history scanning** — walk all commits, scan deleted/modified files
- **Live validation** — confirm found secrets are active against 13 provider APIs
- **.syckignore** — fingerprint + regex pattern suppression of known false positives
- **Multi-layer decoding** — base64, base64url, hex, Unicode escape, URL-encoded, gzip, JWT, double-base64, String.fromCharCode — recursive up to depth 3
- **JS string reconstruction** — constant propagation, concatenation chains, array joins (arbitrary separators), template literals, ternary expressions, array index access
- **JSON-aware scanning** — walks parsed JSON tree under known secret-key names
- **CI gate mode** — `--fail-on` exits non-zero when findings meet severity threshold
- **Zero runtime dependencies** — single static binary, no pip/npm required
- **Endpoint detection** — JS-aware crawl extracts API endpoints from fetch/axios/XHR, 6 frontend router patterns (React/Vue/Angular), 4 GraphQL variants, 3 OpenAPI/Swagger patterns
- **Risk scoring** — 19-rule risk engine assigns 0-10 score per endpoint with FP-safe prefix checking
- **Source map harvesting** — crawler fetches `.js.map` alongside `.js` files, extracts endpoints from map content
- **Juicy file probing** — detects 65 high-value paths: `.env`, `admin`, `actuator/*`, `metrics`, `swagger.json`, backup files, database dumps, terraform state, and more
- **URL secret extraction** — detects `access_token`, `api_key`, `token` etc. leaked in URL query parameters
- **Webhook/SIEM export** — send findings to Slack, Discord, or generic JSON webhooks
- **SQLite cross-run cache** — fingerprint-based dedup across scan runs for progressive triage
- **Adaptive confidence learning** — learns from user verdicts to reduce false positives over time
- **Archive scanning** — extracts and scans zip, tar, tar.gz, jar files with Zip Slip protection
- **Multi-line detection** — matches secrets spanning multiple lines (PEM keys, JSON configs)
- **Auth header detection** — Bearer tokens, Basic auth, API key headers

## Install

```bash
# Latest release (recommended)
go install github.com/RA000WL/syck@latest

# Or download a binary from https://github.com/RA000WL/syck/releases/latest

# Or build from source
git clone https://github.com/RA000WL/syck.git
cd syck
go build -o syck .
```

Requires Go 1.22+.

## Why syck?

| Tool | Approach | Precision | Speed | Decoding | Live validation |
|------|----------|-----------|-------|----------|-----------------|
| syck | Regex + entropy + context + 160 rules + confidence | high | ~50 MB/s | base64, hex, unicode, url, gzip, JWT, charcode, JS recon | Yes (13 providers) |
| gitleaks | Regex only | ~70% | ~80 MB/s | None | No |
| trufflehog | Entropy + regex | noisy | ~20 MB/s | base64 | Yes (limited) |
| detect-secrets | Regex + entropy | ~60% | ~30 MB/s | None | No |

**Real scenario:** syck scans a 5 MB minified JavaScript bundle in under 2 seconds, reconstructs concatenated strings, decodes any base64-encoded tokens inside, and reports findings with line/column/rule/entropy/context — all in one pass.

## Quick Start

```bash
# Scan a directory
syck scan .

# Scan a single file
syck scan path/to/config.js

# Scan a URL (auto-crawl with default settings)
syck scan -u https://example.com/app.js

# Scan from stdin
cat .env | syck scan --pipe

# Critical findings only, redacted output for CI logs
syck scan . --severity CRITICAL --redact --no-color

# JSON output for downstream tooling
syck scan . --format json -o results.json

# SARIF for GitHub Code Scanning
syck scan . --format sarif -o results.sarif
```

**Sample output:**

```
[HIGH]  [stripe_api_key]  config.js:42:18  entropy=4.81
       secret : sk_xxxxxxxxxxxxxxxx
       context: const apiKey = "sk_xxxxxxxxxxxxxxxx";

[HIGH]  [aws_access_key]  env.bak:3:1  entropy=3.92
       secret : AKIAxxxxxxxxxxxxxxxx
       context: AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx

── Summary ──
  Files with findings : 2
  Total findings      : 2
    HIGH      2
```

## Common Workflows

### Pre-commit hook

Save as `.git/hooks/pre-commit`:

```sh
#!/bin/sh
syck scan . --severity CRITICAL --fail-on CRITICAL --quiet --no-color
```

```bash
chmod +x .git/hooks/pre-commit
```

### Container / CI env config

Every flag on the `scan` subcommand can be set via env var. Pattern:
`SYCK_<CMD>_<FLAG>` (uppercase, dashes → underscores).

```bash
# Equivalent to: syck scan . --severity HIGH --format sarif -o results.sarif
export SYCK_SCAN_SEVERITY=HIGH
export SYCK_SCAN_FORMAT=sarif
export SYCK_SCAN_OUTPUT=results.sarif
syck scan . --no-color
```

Useful in Dockerfile / GitHub Actions / Kubernetes containers where CLI
flag escaping is awkward.

### Long-running scans with progress

```bash
# Show a live TUI bar on stderr (auto-disabled by --quiet or --pipe)
syck scan ./very-large-repo --progress
```

The bar reports files scanned, rate, and ETA. Final line shows total
files, elapsed time, and findings count.

### GitHub Action

```yaml
- name: Scan for secrets
  run: |
    go install github.com/RA000WL/syck@latest
    syck scan . --severity HIGH --fail-on HIGH --format sarif -o results.sarif --no-color
- name: Upload SARIF to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

Or use the built-in `syck upload-sarif` (no `codeql-action` dependency):

```yaml
- name: Upload SARIF
  if: always()
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: syck upload-sarif --file results.sarif --repo ${{ github.repository }} --commit ${{ github.sha }}
```

### Generate `.syckignore` from existing findings

```bash
syck scan . --format json | jq -r '.findings[] | "\(.rule):\(.secret):\(.file)"' | \
  while read line; do
    fp=$(echo -n "$line" | sha256sum | cut -d' ' -f1)
    echo "$fp  # $line"
  done > .syckignore
```

### Validate live secrets

```bash
# Confirm found secrets are still active (slower, hits provider APIs)
syck scan . --validate
```

Validation downgrades unconfirmed secrets to `INFO`.

### Adaptive Learning

Train syck to learn from your triage decisions:

```bash
# 1. Scan and save to cache
syck scan . --cache-db scan.db

# 2. Label findings as true/false positive
syck verdict abc123def fp --cache-db scan.db
syck verdict 456789abc tp --cache-db scan.db

# 3. View learning stats
syck verdict --stats --cache-db scan.db

# 4. Scan with adaptive learning enabled
syck scan . --cache-db scan.db --adaptive
```

The system uses Bayesian smoothing with a 90-day decay to gradually learn which rules produce false positives in your codebase. Findings in test/mock/vendor directories are tracked separately. High-certainty rules (AWS keys, GitHub PATs, Stripe keys, private keys) are capped to prevent accidental suppression.

## CLI Reference

### Core Flags

| Flag | Description |
|------|-------------|
| `--severity`, `-s` | Minimum severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default: `LOW`) |
| `--format`, `-f` | Output format: `text`, `json`, `jsonl`, `sarif`, `markdown`, `csv`, `html` (default: `text`) |
| `--output`, `-o` | Write output to file instead of stdout |
| `--redact` | Mask secret values in output (first 4 chars + asterisks) |
| `--no-dedup` | Show all occurrences instead of deduplicating |
| `--exclude`, `-e` | Path exclusion regex (e.g. `--exclude 'test\|vendor'`) |
| `--workers`, `-w` | Concurrent workers (default: 10) |
| `--max-file-size` | Maximum file size to scan (default: `5M`) |
| `--quiet`, `-q` | Suppress banner and warnings |
| `--no-color` | Disable ANSI color output |
| `--config` | Custom config file path |
| `--debug` | Enable debug logging |

### Decoder Flags

| Flag | Description |
|------|-------------|
| `--decode-base64` | Base64 decode lines and rescan |
| `--decode-hex` | Hex decode lines and rescan |
| `--decode-unicode` | Decode `\uXXXX` escapes and rescan |
| `--decode-url` | URL-decode lines and rescan |
| `--decode-gzip` | Decompress gzip/zlib content and rescan |
| `--decode-charcode` | Decode `String.fromCharCode(...)` and rescan |
| `--js-reconstruct` | Reconstruct JS: constant propagation, concat chains, array joins (arbitrary separators), template literals, ternary expressions, array index access (default: **on**) |

### URL Scanning Flags

| Flag | Description |
|------|-------------|
| `--url`, `-u` | URL to scan (can be repeated) |
| `--url-file`, `-l` | File containing URLs to scan (one per line) |
| `--scope` | Regex to filter crawled URLs by domain/path |
| `--crawl-limit` | Max URLs to crawl (default: 100) |
| `--crawl-depth` | Max link follow depth (default: 3) |
| `--headless` | Use headless Chrome for SPA/JS-rendered pages |
| `--rate-limit` | Max requests per second per host (0 = unlimited) |
| `--user-agent` | Custom User-Agent string (empty = random rotation) |
| `--cookies` | Enable cookie jar for session handling (default: true) |
| `--cookie-file` | Persist cookies to file between runs |
| `--concurrency` | Max concurrent fetches (default: 10) |
| `--host-concurrency` | Max concurrent fetches per host (default: 2) |
| `--ignore-robots` | Ignore robots.txt Disallow rules |

### Analysis Flags

| Flag | Description |
|------|-------------|
| `--endpoints` | Extract API, GraphQL, and WebSocket URLs |
| `--min-endpoint-score` | Only show endpoints with risk score >= N (default: 0) |
| `--no-juicy-files` | Disable juicy file probing during endpoint scan |
| `--git-history` | Scan files in git commit history |
| `--validate` | Validate found secrets against provider APIs (live check) |
| `--downgrade-fp` | Downgrade severity for findings in test/mock/vendor dirs and placeholder patterns (default: **on**) |
| `--ignore-file` | Path to `.syckignore` file for fingerprint or regex pattern suppression |
| `--rules`, `-r` | Custom rules YAML file |
| `--pipe` | Scan from stdin |
| `--fail-on` | CI gate: exit 1 if findings meet severity threshold |
| `--multiline` | Enable multi-line pattern matching (sliding window) (default: **on**) |
| `--strip-comments` | Strip comment lines before scanning |
| `--detect-auth-headers` | Detect hardcoded Authorization headers and API keys (default: **on**) |
| `--scan-archives` | Extract and scan inside archives (zip, tar, tar.gz, jar, war, ear) |
| `--scan-binaries` | Extract and scan strings from binary files |
| `--probe-graphql` | Probe GraphQL endpoints with introspection query |
| `--parse-openapi` | Parse OpenAPI/Swagger specs and inject discovered endpoints |
| `--entropy-threshold` | Per-alphabet entropy threshold overrides (e.g. `hex=3.0,base64=4.2`) |
| `--max-scan-line-len` | Skip per-line scanning on lines exceeding this length (default: 100000) |
| `--progress` | Show TUI progress bar on stderr |

### Cache & Adaptive Flags

| Flag | Description |
|------|-------------|
| `--cache-db` | Path to SQLite cache database for cross-run dedup |
| `--adaptive` | Enable adaptive confidence learning from past verdicts |

### Webhook / Export Flags

| Flag | Description |
|------|-------------|
| `--webhook-url` | Send findings to this webhook URL |
| `--webhook-style` | Webhook payload style: `slack`, `discord`, or `json` (default: `json`) |

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

### Other Commands

```bash
# List all detection rules
syck list-rules

# Rule quality testing (precision/recall)
syck ruletest

# Upload SARIF to GitHub Code Scanning
syck upload-sarif --file results.sarif --repo owner/repo --commit SHA

# Adaptive learning verdicts
syck verdict <fingerprint> tp|fp --cache-db scan.db
syck verdict --stats --cache-db scan.db

# Generate shell completion
syck completion bash > /etc/bash_completion.d/syck
```

## Output Formats

| Format | Command | Best For |
|--------|---------|----------|
| Text | `--format text` | Terminal (default, colorized) |
| JSON | `--format json` | Machine parsing, dashboards |
| SARIF | `--format sarif` | GitHub Code Scanning upload |
| Markdown | `--format markdown` | PR comments, reports |
| CSV | `--format csv` | Spreadsheets, data analysis |
| HTML | `--format html` | Browser viewing, dark theme |

## Custom Rules

Create a YAML file and pass it with `--rules`:

```yaml
rules:
  - name: my_internal_api_key
    severity: CRITICAL
    pattern: 'my_internal_key_[a-zA-Z0-9]{32}'
    tags: [internal]
```

```bash
syck scan . --rules my_rules.yaml
```

## .syckignore

Suppress known false positives via two formats: sha256 **fingerprints**
(precise) and `re:`-prefixed **regex patterns** (broad). Patterns match
against the finding's `secret` or `file` field.

```text
# syck .syckignore — one rule per line, # comments ignored

# Fingerprint: sha256("rule:secret:file") — exact-match suppression
a3c12406e369cd1e60910d005904fa526797d2997b523e0b40e8f5347eaf8739

# Pattern: regex matched against secret OR file
re:fonts\.googleapis\.com        # public CDN, no secret value
re:^vendor/                       # all third-party vendor paths
re:\.example\.(com|org)$         # documentation domains
```

```bash
# Generate an ignore file from current findings (fingerprint mode)
syck scan . --format json | python3 -c "
import sys, json, hashlib
data = json.load(sys.stdin)
for f in data['findings']:
    fp = hashlib.sha256(f'{f[\"rule\"]}:{f[\"secret\"]}:{f[\"file\"]}'.encode()).hexdigest()
    print(f'{fp}  # {f[\"rule\"]} in {f[\"file\"]}:{f[\"line\"]}')
" > .syckignore

# Re-scan with ignore file — suppressed findings are filtered out
syck scan . --ignore-file .syckignore
```

**When to use which:**
- **Fingerprint** — known single false positive, never want to see it
- **Pattern** — entire class of FPs (CDN, vendor, mock data, test domains)

## Live Validation

Validate found secrets against provider APIs to confirm they're active:

```bash
syck scan . --validate
```

Supported providers: GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, SendGrid, Twilio, npm, HuggingFace, AWS STS, Slack webhooks, and more.

Validation results downgrade unconfirmed secrets to `INFO` severity.

## CI Integration

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Findings found (or `--fail-on` threshold met) |
| 2 | Bad arguments |

### GitHub Actions Example

```yaml
- name: Run syck
  run: |
    syck scan . --severity HIGH --fail-on HIGH --format sarif -o results.sarif --no-color

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/sh
syck scan . --severity CRITICAL --fail-on CRITICAL --quiet --no-color
```

## Architecture

```
syck scan [paths...]
    │
    ├── File scanning (parallel workers, streaming >1MB)
    ├── URL scanning (goquery → BFS crawl → fetch → scan)
    ├── Git history (git log → git show → scan per-commit)
    └── Stdin pipe
          │
          ├── Regex rules (160+ patterns)
          ├── Entropy token scan + contextual entropy
          ├── Multi-layer decoders (base64/hex/unicode/url/gzip/JWT/charcode)
          ├── JSON-aware tree walker
          ├── JS string reconstruction (6 methods)
          ├── URL secret extraction
          ├── Auth header detection
          └── Endpoint extraction (21 patterns + risk scoring)
               │
               ├── Deduplication
               ├── FP downgrade
               ├── .syckignore filter
               ├── Adaptive learning (--adaptive)
               ├── Live validation (--validate)
               └── Formatter → stdout/file/webhook
```

### Internal Packages

| Package | Purpose |
|---------|---------|
| `scanner` | Core scanning engine (parallel file walk, regex match, entropy, multi-line, auth headers) |
| `rules` | YAML rule loading, compilation, and validation |
| `finding` | Finding/Severity types, confidence scoring, deduplication |
| `decoder` | Base64, base64url, hex, Unicode, URL, gzip, JWT, double-base64, charcode decoding |
| `entropy` | Shannon entropy, per-alphabet thresholds, media token filtering, contextual secrets |
| `formatters` | Text, JSON, SARIF, Markdown, CSV, HTML, webhook/SIEM output |
| `endpoints` | API/GraphQL/WebSocket URL extraction |
| `crawler` | BFS URL crawler with goquery, cookies, rate limiting, archive extraction |
| `gitscan` | Git commit history walking |
| `ignore` | .syckignore fingerprint loading and filtering |
| `validator` | Live secret validation against 13 providers |
| `json_scanner` | JSON tree walking for secret-key values |
| `jsrecon` | JS constant propagation, concat/join/template/ternary/array reconstruction |
| `risk` | Endpoint risk scoring (19 rules, FP-safe prefix check) |
| `correlator` | SQLite cross-run finding cache with fingerprint dedup |
| `adaptive` | Adaptive confidence learning engine (Bayesian smoothing, tier classification, weight store) |
| `correlation` | Multi-finding correlation (AWS key+secret pairs, OAuth, Stripe, etc.) |
| `confidence` | Confidence scoring engine (regex/entropy/context/decoded/URL param sources) |
| `recon` | HTTP response recon (admin panels, debug endpoints, GraphQL, staging, metrics) |
| `url_secrets` | URL query parameter secret extraction |


syck eliminates false positives from overly broad patterns while catching all true positives.

## Contributing

```bash
# Fork + clone
git clone https://github.com/YOUR_USERNAME/syck.git
cd syck

# Make a branch
git checkout -b feature/my-rule

# Run tests
go test -race ./...

# Run rule quality tests
syck ruletest

# Verify gofmt + vet
gofmt -l .
go vet ./...

# Commit + push + open a PR
git commit -m "feat(rules): add my_internal_api_key pattern"
git push origin feature/my-rule
```

**Adding a new rule:** Edit `internal/rules/builtin.yaml`, then add positive + negative test fixtures under `internal/ruletest/testdata/`. Run `go run . ruletest` to verify precision/recall before pushing.

**Code style:** `gofmt` + `go vet` + `go test -race ./...` must all pass. No new top-level dependencies without discussion.

## License

MIT
