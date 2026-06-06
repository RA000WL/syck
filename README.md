# syck

[![CI](https://github.com/RA000WL/syck/actions/workflows/ci.yml/badge.svg)](https://github.com/RA000WL/syck/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RA000WL/syck)](https://github.com/RA000WL/syck/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)

A fast, modular secret scanner written in Go. 130+ detection rules, multi-layer decoding, entropy analysis, URL crawling, and live secret validation — all in a single static binary.

**Why syck?** Most secret scanners either miss too much (regex-only) or drown you in false positives (entropy-only). syck combines both with rule-specific context keywords, decoder layers, and a precision-hardened rule set that scores 100% precision on the curated test corpus (vs. 11.9% for the Python reference).

## Features

- **130+ detection rules** — AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, and 50+ providers
- **Entropy analysis** — Shannon entropy scoring catches high-entropy tokens that regex alone misses
- **6 output formats** — text, JSON, SARIF 2.1.0, Markdown, CSV, dark-themed HTML
- **URL crawling** — BFS crawler with goquery HTML extraction, per-host rate limiting, scope filtering
- **Headless Chrome** — SPA/JS-rendered page support via go-rod
- **Git history scanning** — walk all commits, scan deleted/modified files
- **Live validation** — confirm found secrets are active against 13 provider APIs
- **.syckignore** — fingerprint-based suppression of known false positives
- **Multi-layer decoding** — base64, hex, Unicode escape, URL-encoded, gzip, recursive up to depth 4
- **JS string reconstruction** — concat chains, array joins, template literals
- **JSON-aware scanning** — walks parsed JSON tree under known secret-key names
- **CI gate mode** — `--fail-on` exits non-zero when findings meet severity threshold
- **Zero runtime dependencies** — single static binary, no pip/npm required

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
| syck | Regex + entropy + context + 130 rules | 100% (test corpus) | ~50 MB/s | base64, hex, unicode, url, gzip, JS | Yes (13 providers) |
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

## CLI Reference

### Core Flags

| Flag | Description |
|------|-------------|
| `--severity`, `-s` | Minimum severity: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default: `LOW`) |
| `--format`, `-f` | Output format: `text`, `json`, `sarif`, `markdown`, `csv`, `html` (default: `text`) |
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
| `--js-reconstruct` | Reconstruct JS concatenated strings, array joins, template literals |

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
| `--git-history` | Scan files in git commit history |
| `--validate` | Validate found secrets against provider APIs (live check) |
| `--downgrade-fp` | Downgrade severity for findings in test/mock/vendor dirs |
| `--ignore-file` | Path to `.syckignore` file for fingerprint-based suppression |
| `--rules`, `-r` | Custom rules YAML file |
| `--pipe` | Scan from stdin |
| `--fail-on` | CI gate: exit 1 if findings meet severity threshold |

### Other Commands

```bash
# List all detection rules
./syck list-rules

# Generate shell completion
./syck completion bash > /etc/bash_completion.d/syck
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
./syck scan . --rules my_rules.yaml
```

## .syckignore

Suppress known false positives using fingerprints:

```bash
# Generate an ignore file from current findings
./syck scan . --format json | python3 -c "
import sys, json, hashlib
data = json.load(sys.stdin)
for f in data['findings']:
    fp = hashlib.sha256(f'{f[\"rule\"]}:{f[\"secret\"]}:{f[\"file\"]}'.encode()).hexdigest()
    print(f'{fp}  # {f[\"rule\"]} in {f[\"file\"]}:{f[\"line\"]}')
" > .syckignore

# Re-scan with ignore file — suppressed findings are filtered out
./syck scan . --ignore-file .syckignore
```

## Live Validation

Validate found secrets against provider APIs to confirm they're active:

```bash
./syck scan . --validate
```

Supported providers: GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, SendGrid, Twilio, npm, HuggingFace, Slack webhooks, and more.

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
    ./syck scan . --severity HIGH --fail-on HIGH --format sarif -o results.sarif --no-color

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
#!/bin/sh
./syck scan . --severity CRITICAL --fail-on CRITICAL --quiet --no-color
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
         ├── Regex rules (130+ patterns)
         ├── Entropy token scan
         ├── Multi-layer decoders (base64/hex/unicode/url/gzip)
         ├── JSON-aware tree walker
         └── JS string reconstruction
              │
              ├── Deduplication
              ├── FP downgrade
              ├── .syckignore filter
              ├── Live validation (--validate)
              └── Formatter → stdout/file
```

### Internal Packages

| Package | Purpose |
|---------|---------|
| `scanner` | Core scanning engine (parallel file walk, regex match, entropy) |
| `rules` | YAML rule loading and compilation |
| `finding` | Finding/Severity types, deduplication |
| `decoder` | Base64, hex, Unicode, URL decoding |
| `entropy` | Shannon entropy calculation |
| `formatters` | Text, JSON, SARIF, Markdown, CSV, HTML output |
| `endpoints` | API/GraphQL/WebSocket URL extraction |
| `crawler` | BFS URL crawler with goquery, cookies, rate limiting |
| `gitscan` | Git commit history walking |
| `ignore` | .syckignore fingerprint loading and filtering |
| `validator` | Live secret validation against 13 providers |
| `json_scanner` | JSON tree walking for secret-key values |
| `jsrecon` | JS concat/join/template string reconstruction |


syck eliminates false positives from overly broad patterns while catching all true positives.

## Contributing

```bash
# Fork + clone
git clone https://github.com/YOUR_USERNAME/syck.git
cd syck

# Make a branch
git checkout -b feature/my-rule

# Run tests
go test ./...

# Run rule quality tests
go run . ruletest

# Verify gofmt + vet
gofmt -l .
go vet ./...

# Commit + push + open a PR
git commit -m "feat(rules): add my_internal_api_key pattern"
git push origin feature/my-rule
```

**Adding a new rule:** Edit `internal/rules/builtin.yaml`, then add positive + negative test fixtures under `internal/ruletest/testdata/`. Run `go run . ruletest` to verify precision/recall before pushing.

**Code style:** `gofmt` + `go vet` + `golangci-lint` must all pass. No new top-level dependencies without discussion.

## License

MIT
