# SYCK (SecretsYouCantKeep)

[![CI](https://github.com/RA000WL/syck/actions/workflows/ci.yml/badge.svg)](https://github.com/RA000WL/syck/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RA000WL/syck)](https://github.com/RA000WL/syck/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)

A fast, modular secret scanner and recon engine written in Go. 200+ detection rules, multi-layer decoding, entropy analysis, URL crawling, JavaScript analysis, endpoint extraction, subdomain discovery, security header analysis, technology fingerprinting, and live secret validation — all in a single static binary.

## Features

### Core Scanning
- **200+ detection rules** — AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, SendGrid, Terraform, Firebase, Kubernetes, Docker, email/password hashes, PII, and 50+ providers
- **Entropy analysis** — Shannon entropy scoring with per-alphabet thresholds and media token filtering
- **Confidence scoring** — numeric 0-100 confidence with LOW/MEDIUM/HIGH/CRITICAL bands and detection method tags
- **Contextual entropy** — keyword-gated entropy detection finds secrets even without specific rule matches
- **Multi-layer decoding** — base64, base64url, hex, Unicode escape, URL-encoded, gzip, JWT, double-base64, String.fromCharCode — recursive up to depth 3

### JavaScript & Source Analysis
- **JS string reconstruction** — constant propagation, concatenation chains, array joins, template literals, ternary expressions, array index access
- **Environment variable detection** — `process.env.*`, `import.meta.env.*`, `$ENV_VAR` patterns
- **Dynamic import extraction** — `import()`, `require()`, lazy loading patterns
- **Hidden secret detection** — config secrets, base64 encoded values, TODO/FIXME leaks
- **Debug artifact detection** — development URLs, debug endpoints, localhost references
- **Sensitive file references** — `.env`, `.key`, `.pem`, credentials files

### Reconnaissance & Discovery
- **Subdomain enumeration** — Certificate Transparency (crt.sh + CertSpotter) + DNS bruteforce wordlist
- **Internal link detection** — private IPs (10.x, 172.16-31.x, 192.168.x), cloud metadata (169.254.169.254), Kubernetes/Docker services, localhost, sensitive ports
- **Endpoint extraction** — 30+ patterns: API versioning, REST, GraphQL, gRPC, webhooks, debug/admin, internal paths, frontend routers
- **Juicy file probing** — 150+ high-value paths: `.env`, `admin`, `actuator/*`, `.well-known/*`, source maps, backup files, CI/CD configs, database dumps
- **GraphQL introspection** — schema analysis for sensitive queries and mutations

### Security Analysis
- **Security header analysis** — CSP, HSTS, X-Frame-Options, CORS misconfigurations, cookie security, server version disclosure (18 finding types)
- **Technology fingerprinting** — CMS, frameworks, languages, libraries, CDNs from HTTP responses and source code
- **WAF/CDN detection** — Cloudflare, Akamai, AWS CloudFront, and more
- **Cloud storage detection** — S3, GCS, Azure Blob URL patterns

### Output & Integration
- **7 output formats** — text (professional with severity icons), JSON, JSONL/NDJSON, SARIF 2.1.0, Markdown, CSV, dark-themed HTML
- **URL crawling** — BFS crawler with goquery HTML extraction, per-host rate limiting, scope filtering, sitemap discovery
- **Headless Chrome** — SPA/JS-rendered page support via go-rod
- **Git history scanning** — walk all commits, scan deleted/modified files
- **Live validation** — confirm found secrets are active against 13 provider APIs
- **Webhook/SIEM export** — send findings to Slack, Discord, or generic JSON webhooks
- **SQLite cross-run cache** — fingerprint-based dedup across scan runs for progressive triage
- **Adaptive confidence learning** — learns from user verdicts to reduce false positives over time

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

Requires Go 1.26+.

## Quick Start

```bash
# Scan a directory
syck scan .

# Scan a single file
syck scan path/to/config.js

# Scan a URL (auto-crawl with default settings)
syck scan -u https://example.com/app.js

# Scan from stdin (auto-detects URLs vs raw content)
cat urls.txt | syck scan --pipe
echo "const API_KEY = 'sk_live_...'" | syck scan --pipe

# Scan URLs from file
syck scan -l urls.txt --scope "example.com"

# Critical findings only, redacted output for CI logs
syck scan . --severity CRITICAL --redact --no-color

# JSON output for downstream tooling
syck scan . --format json -o results.json

# SARIF for GitHub Code Scanning
syck scan . --format sarif -o results.sarif

# Full recon with endpoints
syck scan -u https://example.com --endpoints --crawl-limit 100
```

**Sample output:**

```
╔════════════════════════════════════════════════════════════╗
║  syck v1.1.0                                              ║
║  Secret Scanner & Recon Engine                             ║
╚════════════════════════════════════════════════════════════╝

⚠  WARNING: Secrets are shown in full. Do not share this output.

┌─ config.js
│ 🔴 CRITICAL │ CRITICAL │ aws_access_key_id             │ AKIAIOSFODNN7EXAMPLE
│   AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
│ 🟠 HIGH     │ HIGH     │ stripe_api_key                │ sk_live_xxxxxxxxxxxxxxxx
│   const apiKey = "sk_live_xxxxxxxxxxxxxxxx";

─── Scan Complete ────────────────────────────────────────────

  Files scanned    : 1
  Total findings   : 2

  Severity Distribution:
    CRITICAL  ████████████████████████████░░ 1
    HIGH      ████████████████████████████░░ 1
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

### Long-running scans with progress

```bash
# Show a live TUI bar on stderr (auto-disabled by --quiet or --pipe)
syck scan ./very-large-repo --progress
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

### Bug Bounty Recon

```bash
# Full recon with subdomain discovery
syck scan -u https://target.com --endpoints --crawl-limit 500

# Scan with proxy (Burp Suite)
syck scan -u https://target.com --proxy http://127.0.0.1:8080

# Pipe URLs from other tools
cat subdomains.txt | syck scan --pipe --scope "target.com"

# Scan JS files for secrets
syck scan ./downloaded_js/ --endpoints --decode-base64
```

### Validate live secrets

```bash
# Confirm found secrets are still active (slower, hits provider APIs)
syck scan . --validate
```

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
| `--js-reconstruct` | Reconstruct JS strings (default: **on**) |

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
| `--endpoints` | Extract API, GraphQL, WebSocket, and internal URLs |
| `--min-endpoint-score` | Only show endpoints with risk score >= N (default: 0) |
| `--no-juicy-files` | Disable juicy file probing during endpoint scan |
| `--git-history` | Scan files in git commit history |
| `--validate` | Validate found secrets against provider APIs (live check) |
| `--downgrade-fp` | Downgrade severity for findings in test/mock/vendor dirs (default: **on**) |
| `--ignore-file` | Path to `.syckignore` file |
| `--rules`, `-r` | Custom rules YAML file |
| `--pipe` | Scan from stdin (auto-detects URLs vs raw content) |
| `--fail-on` | CI gate: exit 1 if findings meet severity threshold |
| `--multiline` | Enable multi-line pattern matching (default: **on**) |
| `--strip-comments` | Strip comment lines before scanning |
| `--detect-auth-headers` | Detect hardcoded Authorization headers (default: **on**) |
| `--scan-archives` | Extract and scan inside archives (zip, tar, jar, war, ear) |
| `--scan-binaries` | Extract and scan strings from binary files |
| `--probe-graphql` | Probe GraphQL endpoints with introspection query |
| `--parse-openapi` | Parse OpenAPI/Swagger specs and inject discovered endpoints |
| `--header-check` | Analyze HTTP security headers (default: **on**) |
| `--tech-detect` | Detect technologies from HTTP responses and source code (default: **on**) |

### Recon Flags

| Flag | Description |
|------|-------------|
| `--recon` | Auto-discover subdomains before scanning (crt.sh + CertSpotter) |
| `--recon-wayback` | Include Wayback Machine URLs in recon |
| `--recon-live` | Only scan live hosts from recon |

### Cache & Adaptive Flags

| Flag | Description |
|------|-------------|
| `--cache-db` | Path to SQLite cache database for cross-run dedup |
| `--adaptive` | Enable adaptive confidence learning from past verdicts |
| `--url-cache-db` | Path to SQLite URL cache for cross-run crawl dedup |

### Bug Bounty Flags

| Flag | Description |
|------|-------------|
| `--proxy` | Route all HTTP traffic through a proxy (e.g. Burp Suite) |
| `--auth-token` | Bearer token for authenticated crawling |
| `--header` | Custom header (repeatable): `--header "Name: Value"` |
| `--scope-file` | File with scope regex patterns (one per line) |
| `--cookie` | Cookie string: `--cookie "session=abc; token=xyz"` |
| `--no-sitemap` | Disable robots.txt/sitemap.xml discovery |
| `--diff` | Only show new findings (requires `--cache-db`) |
| `--http-timeout` | HTTP timeout (default `10s`) |

## Output Formats

| Format | Command | Best For |
|--------|---------|----------|
| Text | `--format text` | Terminal (default, colorized with severity icons) |
| JSON | `--format json` | Machine parsing, dashboards |
| JSONL | `--format jsonl` | Streaming/piping, one finding per line |
| SARIF | `--format sarif` | GitHub Code Scanning upload |
| Markdown | `--format markdown` | PR comments, reports |
| CSV | `--format csv` | Spreadsheets, data analysis |
| HTML | `--format html` | Browser viewing, dark theme |

## Architecture

```
syck scan [paths...]
    │
    ├── File scanning (parallel workers, streaming >1MB)
    ├── URL scanning (goquery → BFS crawl → fetch → scan)
    ├── Stdin pipe (auto-detects URLs vs raw content)
    └── Git history (git log → git show → scan per-commit)
          │
          ├── Regex rules (200+ patterns)
          ├── Entropy token scan + contextual entropy
          ├── Multi-layer decoders (base64/hex/unicode/url/gzip/JWT/charcode)
          ├── JSON-aware tree walker
          ├── JS string reconstruction (6 methods)
          ├── JS/Source analysis (env vars, secrets, internal URLs)
          ├── URL secret extraction
          ├── Auth header detection
          ├── Endpoint extraction (30+ patterns + risk scoring)
          ├── Security header analysis (18 finding types)
          ├── Technology fingerprinting (40+ signals)
          ├── WAF/CDN detection
          └── Cloud storage detection
               │
               ├── Deduplication
               ├── FP downgrade
               ├── .syckignore filter
               ├── Diff mode (--diff)
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
| `formatters` | Text, JSON, JSONL, SARIF, Markdown, CSV, HTML, webhook/SIEM output |
| `endpoints` | API/GraphQL/WebSocket/internal URL extraction (30+ patterns) |
| `crawler` | BFS URL crawler with goquery, cookies, rate limiting, archive extraction |
| `jsanalysis` | JavaScript/source analysis (env vars, secrets, internal URLs, debug artifacts) |
| `jsrecon` | JS constant propagation, concat/join/template/ternary/array reconstruction |
| `discovery` | Subdomain enumeration (crt.sh, CertSpotter, DNS bruteforce) |
| `recon` | Attack surface detection (admin, auth, debug, GraphQL, internal, metrics, staging, headers, tech, WAF) |
| `gitscan` | Git commit history walking |
| `ignore` | .syckignore fingerprint loading and filtering |
| `validator` | Live secret validation against 13 providers |
| `json_scanner` | JSON tree walking for secret-key values |
| `correlator` | SQLite cross-run finding cache with fingerprint dedup |
| `adaptive` | Adaptive confidence learning engine (Bayesian smoothing, tier classification, weight store) |
| `correlation` | Multi-finding correlation (AWS key+secret pairs, OAuth, Stripe, etc.) |
| `confidence` | Confidence scoring engine |
| `httpclient` | Shared HTTP client factory with connection pooling, proxy, TLS support |

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

## License

MIT
