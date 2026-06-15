# SYCK Architecture Reference

> Living document for contributors, AI agents, and future maintainers. Covers design decisions, data flow, key interfaces, and package responsibilities.

---

## Table of Contents

1. [Project Identity](#1-project-identity)
2. [Design Philosophy](#2-design-philosophy)
3. [Directory Layout](#3-directory-layout)
4. [Core Pipeline](#4-core-pipeline)
5. [Detection Engine (9 Layers)](#5-detection-engine-9-layers)
6. [Key Types & Interfaces](#6-key-types--interfaces)
7. [Package Map](#7-package-map)
8. [Data Flow: End to End](#8-data-flow-end-to-end)
9. [Scanning Modes](#9-scanning-modes)
10. [Post-Processing Pipeline](#10-post-processing-pipeline)
11. [Output Formats](#11-output-formats)
12. [Confidence & Risk Scoring](#12-confidence--risk-scoring)
13. [Live Validation](#13-live-validation)
14. [External Integrations](#14-external-integrations)
15. [CLI Reference](#15-cli-reference)
16. [Rule System](#16-rule-system)
17. [Testing Strategy](#17-testing-strategy)
18. [Build & Release](#18-build--release)
19. [Contributing Guidelines](#19-contributing-guidelines)
20. [Version History](#20-version-history)

---

## 1. Project Identity

| Attribute | Value |
|-----------|-------|
| Name | **SYCK** (SecretsYouCantKeep) |
| Language | Go 1.26+ |
| Module Path | `github.com/RA000WL/syck` |
| License | MIT |
| Current Version | 1.1.0 (V1.3+ features on main) |
| Binary | Single static binary, zero runtime dependencies |
| Purpose | Detect hardcoded secrets, API keys, tokens, passwords, and credentials in source code, configs, web pages, and binaries |

### What Makes It Different

Most scanners fall into two camps:
- **Regex-only** (gitleaks): misses obfuscated/encoded secrets
- **Entropy-only** (trufflehog): drowns users in false positives

SYCK combines both with context keywords, multi-layer decoding, JS string reconstruction, live validation, and confidence scoring into a unified pipeline.

---

## 2. Design Philosophy

1. **Layered detection** — no single technique catches everything. Regex, entropy, context, decoding, and reconstruction are stacked.
2. **Recursive decoding** — secrets hidden in base64, hex, JWT, etc. are decoded and re-scanned up to depth 3.
3. **JS-aware analysis** — JavaScript string obfuscation (concat, join, template literals, ternaries) is reversed before scanning.
4. **Confidence over severity** — severity is what the rule says; confidence is how sure we are. Both live on every Finding.
5. **Progressive triage** — SQLite cache enables cross-run dedup so teams can focus on new findings.
6. **Zero-config defaults** — works out of the box; every behavior is tunable via 60+ flags.

---

## 3. Directory Layout

```
syck-go/
├── main.go                         # Entry point → cmd.Execute()
├── go.mod / go.sum                 # Module + dependencies
├── Makefile                        # build, test, vet, clean, lint
├── .goreleaser.yaml                # Release config (linux/darwin/windows x amd64/arm64)
├── .syckignore                     # Self-suppression (eats its own dogfood)
├── README.md                       # User-facing docs
├── ARCHITECTURE.md                 # This file
│
├── cmd/                            # CLI layer (cobra)
│   ├── root.go                     # Root command, version flags, persistent flags
│   ├── scan.go                     # Main scan command — 67 flags, orchestrates pipeline
│   ├── list_rules.go               # List all detection rules
│   ├── ruletest.go                 # Rule quality testing harness
│   ├── upload_sarif.go             # Upload SARIF to GitHub Code Scanning
│   ├── verdict.go                  # Record true/false positive verdicts for adaptive learning
│   ├── version.go                  # Print version/commit/date
│   └── env.go                      # SYCK_* environment variable binding
│
├── config/
│   └── config.go                   # Viper-based config loading (JSON)
│
├── internal/                       # All internal packages (not importable)
│   ├── rules/                      # Rule loading, compilation, validation
│   │   ├── builtin.yaml            # 188 embedded rules (876 lines)
│   │   ├── rule.go                 # Rule/RuleSet types, matching
│   │   ├── load.go                 # YAML loading, embedding, RuleLoader
│   │   ├── compile.go              # Thread-safe regex compilation cache
│   │   └── validate.go             # Rule validation (names, severities, duplicates)
│   │
│   ├── scanner/                    # Core scanning engine
│   │   ├── scanner.go              # Config struct (51 fields)
│   │   ├── scan.go                 # ScanPaths, ScanFile, ScanReader, ScanURLs, ScanContent
│   │   ├── pipeline.go             # V1 Pipeline type (8 typed stages)
│   │   ├── stage_*.go              # Individual pipeline stages
│   │   ├── multiline.go            # Multi-line pattern matching (sliding window)
│   │   ├── auth_header.go          # Bearer/Basic/API key detection
│   │   ├── binary.go               # Binary string extraction
│   │   ├── downgrade.go            # FP downgrade for test/mock/vendor
│   │   ├── strip.go                # Comment line stripping
│   │   ├── url_secrets.go          # URL query parameter extraction
│   │   ├── techsource.go           # Source code technology fingerprinting
│   │   ├── cookie_parser.go        # Browser-style cookie header parsing
│   │   └── header_transport.go     # HTTP RoundTripper for custom header injection
│   │
│   ├── entropy/                    # Entropy analysis
│   │   ├── entropy.go              # Shannon entropy, context gating, media filter
│   │   └── alphabet.go             # Alphabet detection (hex, base64, JWT)
│   │
│   ├── decoder/                    # Multi-layer decoding
│   │   ├── decoders.go             # Base64, hex, unicode, URL decoders
│   │   ├── registry.go             # Decoder registry pattern
│   │   ├── pipeline.go             # Recursive decode-and-rescan (depth 3)
│   │   ├── charcode.go             # String.fromCharCode decoder
│   │   ├── jwt.go                  # JWT payload decoder
│   │   ├── base64url.go            # Base64URL decoder
│   │   └── doublebase64.go         # Double-base64 decoder
│   │
│   ├── finding/                    # Finding types
│   │   └── finding.go              # Finding struct, Severity, Dedup, Summary
│   │
│   ├── confidence/                 # Confidence scoring
│   │   └── confidence.go           # Multi-signal scorer
│   │
│   ├── correlation/                # Multi-finding correlation
│   │   ├── correlation.go          # Correlator + Detector interface
│   │   ├── helpers.go              # Shared helpers
│   │   └── detector_*.go           # 8 detectors (AWS, Cloudflare, DB, GitHub, JWT, OAuth, Stripe, Twilio)
│   │
│   ├── correlator/                 # SQLite cross-run cache
│   │   └── cache.go                # SHA256 fingerprinting, INSERT-or-UPDATE
│   │
│   ├── adaptive/                   # Adaptive confidence learning engine
│   │   └── adaptive.go             # Tier types, Bayesian smoothing, modifier, weight store, decay
│   │
│   ├── endpoints/                  # API endpoint extraction
│   │   ├── extract.go              # 17 regex patterns
│   │   └── risk.go                 # 14 risk scoring rules in 7 groups
│   │
│   ├── crawler/                    # Web crawling
│   │   ├── crawler.go              # BFS crawler with parallel fetching
│   │   ├── extract.go              # URL extraction from HTML
│   │   ├── parallel.go             # Host-semaphore concurrency control
│   │   ├── headless.go             # Headless Chrome (go-rod)
│   │   ├── cookies.go              # Cookie jar persistence
│   │   ├── robots.go               # robots.txt parsing
│   │   ├── useragent.go            # Random user-agent rotation
│   │   ├── encoding.go             # Character encoding detection
│   │   ├── juicy.go                # High-value path probing (65 paths)
│   │   ├── cloud_storage.go        # S3/GCS/Azure URL detection
│   │   ├── graphql_introspect.go   # GraphQL introspection probe
│   │   ├── openapi.go              # OpenAPI/Swagger spec parser
│   │   ├── archive.go              # Zip/tar/tar.gz/jar extraction (Zip Slip protection)
│   │   ├── packages.go             # Package file scanning (npm/yarn/go/cargo)
│   │   ├── urlcache.go             # SQLite cross-run URL dedup cache
│   │   └── sitemap.go              # Sitemap XML parsing and fetching
│   │
│   ├── jsrecon/                    # JS string reconstruction
│   │   ├── reconstruct.go          # 6 methods (concat, join, template, const, ternary, array index)
│   │   ├── analyze.go              # JS request analysis (fetch/axios/XHR/Apollo)
│   │   └── jsrequest.go            # JSRequest type
│   │
│   ├── json_scanner/               # JSON-aware scanning
│   │   └── scanner.go              # Tree-walking scanner
│   │
│   ├── gitscan/                    # Git history scanning
│   │   └── scanner.go              # Walk commits, extract files, scan per-commit
│   │
│   ├── formatters/                 # Output formatting
│   │   ├── formatter.go            # Formatter interface + factory
│   │   ├── text.go                 # Colorized terminal
│   │   ├── json.go                 # Structured JSON
│   │   ├── jsonl.go                # JSONL/NDJSON (one finding per line)
│   │   ├── sarif.go                # SARIF 2.1.0
│   │   ├── markdown.go             # Markdown tables
│   │   ├── csv.go                  # CSV
│   │   ├── html.go                 # Dark-themed HTML
│   │   ├── webhook.go              # Slack/Discord/JSON webhook export
│   │   └── summary.go              # ScanSummary with distributions
│   │
│   ├── validator/                  # Live secret validation
│   │   ├── validator.go            # Validator interface + registry
│   │   ├── http.go                 # Shared HTTP client with rate limiting
│   │   ├── ratelimit.go            # Per-host token bucket rate limiter
│   │   └── provider_*.go           # 13 provider implementations
│   │
│   ├── recon/                      # Attack surface detection
│   │   ├── recon.go                # Registry + SurfaceFinding type
│   │   └── detector_*.go           # 11 detectors (admin, auth, debug, graphql, headers, internal, metrics, staging, storage, swagger, techweb)
│   │
│   ├── ignore/                     # .syckignore support
│   │   └── ignore.go               # Fingerprint + regex pattern suppression
│   │
│   ├── progress/                   # TUI progress bar
│   │   └── progress.go             # schollz/progressbar wrapper
│   │
│   └── ruletest/                   # Rule quality testing
│       ├── harness.go              # Test harness (precision/recall/FP rate)
│       ├── report.go               # Test reporting
│       ├── corpus.go               # Positive/negative corpus loading
│       └── generate.go             # Corpus generation utilities
│
│   └── httpclient/                 # Shared HTTP client factory
│       └── client.go               # Transport + client with proxy, TLS, timeout support
│
├── docs/                           # Design docs and specs
│   ├── examples/
│   │   └── github-actions.yml      # Example CI workflow
│   └── superpowers/                # Design specs and implementation plans
│       ├── specs/                  # Design specs
│       └── plans/                  # Implementation plans
│
└── .github/
    ├── workflows/
    │   ├── ci.yml                  # CI (build, gofmt, vet, test -race, lint)
    │   ├── release.yml             # GoReleaser on tag push
    │   └── ruletest.yml            # Rule quality CI
    └── secret_scanning.yml         # Push protection paths-ignore
```

---

## 4. Core Pipeline

### Active Execution Path (V6 Entry Points)

The CLI currently uses the **V6 inline orchestration** path. The V1 Pipeline type exists but is not the primary execution path.

```
cmd/scan.go
  │
  ├── File paths  → scanner.ScanPaths()  → filepath.Walk + parallel ScanFile()
  ├── URLs        → scanner.ScanURLs()   → crawler.Crawl() BFS + per-URL scanning
  ├── Stdin       → scanner.ScanReader() → buffered read + scanContent()
  └── Git history → gitscan.ScanHistory() → git log/show per-commit
```

### V1 Pipeline (Structured — for reference)

```go
// internal/scanner/pipeline.go
type Pipeline struct {
    Rule, Collector, Decoder, Entropy, Correlation,
    Verifier, Confidence, Reporter *Stage
}
// Order: Collector → Decoder → Rule → Entropy → Correlation → Verifier → Confidence → Reporter
```

---

## 5. Detection Engine (9 Layers)

SYCK uses a **multi-layer detection approach** where each layer catches different types of secrets:

### Layer 1: Regex Pattern Matching
- **188 rules** in `internal/rules/builtin.yaml`
- Each rule: name, severity, regex pattern, tags, optional entropy threshold, context keywords
- Compiled once at startup with thread-safe caching (`internal/rules/compile.go`)
- All rules matched against every line of every file

### Layer 2: Entropy Analysis
- Shannon entropy calculation (`entropy.Shannon()`)
- Context-gated: only fires on lines containing secret-related keywords
- Per-alphabet thresholds: hex ≥ 3.0, base64/JWT ≥ 4.0, unknown ≥ 4.5
- Media token filtering: detects 15 base64-encoded media formats (PNG, JPEG, GIF, etc.) to avoid FPs

### Layer 3: Contextual Entropy
- `ExtractContextualSecrets()`: keyword-gated entropy detection for tokens ≥ 20 chars with entropy ≥ 4.5
- Finds secrets even without specific rule matches

### Layer 4: Multi-Layer Decoding
- 9 decoder types applied recursively up to depth 3
- Decoded content is re-scanned against all rules
- Decoders: base64, base64url, hex, unicode escape, URL encoding, gzip/zlib, JWT payload, double-base64, String.fromCharCode

### Layer 5: JS String Reconstruction
- Constant propagation (var/let/const chains)
- Concatenation chain resolution
- Array join with arbitrary separators
- Template literal extraction
- Ternary expression extraction (both branches)
- Array index access resolution
- All reconstructed strings ≥ 20 chars re-scanned

### Layer 6: JSON-Aware Scanning
- Parses JSON files and walks the tree
- Matches values under keys matching 30+ secret-key patterns (password, token, api_key, etc.)

### Layer 7: URL Secret Extraction
- Parses URLs found in source code
- Extracts secrets from query parameters: access_token, token, api_key, auth, jwt, bearer, key, secret

### Layer 8: Auth Header Detection
- Bearer token patterns
- Basic auth patterns
- API key header patterns
- Auth token header patterns

### Layer 9: Binary String Extraction
- Extracts printable UTF-8 strings ≥ 8 bytes from binary files
- Scans extracted strings through the normal detection pipeline

---

## 6. Key Types & Interfaces

### Finding (`internal/finding/finding.go`)

The central data type — every detection produces one or more Findings:

```go
type Finding struct {
    File, RuleName, Secret, Context string
    ContextBefore, ContextAfter    string
    Line, Column                   int
    Severity                       Severity  // 0-4: INFO/LOW/MEDIUM/HIGH/CRITICAL
    Entropy                        float64
    RiskScore                      int       // 0-10 (endpoint risk)
    Confidence                     int       // 0-100 numeric
    ConfidenceBand                 string    // LOW/MEDIUM/HIGH/CRITICAL
    DetectionMethod                string    // regex/entropy/context/decoded/url_param
    VerificationStatus             string    // VERIFIED/LIKELY/POTENTIAL/UNVERIFIED
    DecodedValuePreview            string
    FirstSeen, LastSeen            string
    IsNew                          bool
    AdaptiveModifier               int       // -40 to +40 (adaptive learning adjustment)
    LearningTier                   string    // Experimental/Learning/Mature/Trusted
}
```

### Rule (`internal/rules/rule.go`)

```go
type Rule struct {
    Name             string
    Description      string
    Severity         string
    Pattern          string   // regex
    Version          string
    Tags             []string
    EntropyThreshold float64
    ContextKeywords  []string
    RequiresContext  bool
    Verify           bool
    MultiLine        bool
    compiled         *regexp.Regexp  // thread-safe compiled
}
```

### Formatter Interface (`internal/formatters/formatter.go`)

```go
type Formatter interface {
    Format(findings []finding.Finding, opts FormatOptions) (string, error)
}
// Implementations: TextFormatter, JSONFormatter, JSONLFormatter,
//                  SARIFFormatter, MarkdownFormatter, CSVFormatter, HTMLFormatter
```

### Validator Interface (`internal/validator/validator.go`)

```go
type Validator interface {
    Name() string
    Validate(secret string) ValidationResult
}
// 13 implementations: GitHub, GitLab, Slack, Slack Webhook, Stripe,
// OpenAI (×2), Anthropic, SendGrid, Twilio, npm, HuggingFace, AWS
```

### Decoder (`internal/decoder/registry.go`)

```go
type Decoder func(string) []DecodeResult
type DecodeResult struct {
    SourceTag string  // "base64", "hex", etc.
    Text      string  // decoded content
}
// 9 registered decoders
```

### Correlation Detector (`internal/correlation/correlation.go`)

```go
type Detector interface {
    Match(findings []finding.Finding) []CorrelatedFinding
}
// 8 implementations: AWS, Cloudflare, Database URL, GitHub App,
// JWT, OAuth, Stripe, Twilio
```

### Recon Detector (`internal/recon/recon.go`)

```go
type Detector interface {
    Detect(urls []string) []SurfaceFinding
}
// 11 implementations: Admin, Auth, Debug, GraphQL, Headers, Internal,
// Metrics, Staging, Storage, Swagger, TechFingerprintWeb
```

### Scanner Config (`internal/scanner/scanner.go`)

Central configuration struct with 51 fields controlling every aspect of scanning behavior. Passed through the entire pipeline.

---

## 7. Package Map

| Package | Lines | Responsibility |
|---------|-------|----------------|
| `cmd/` | ~1000 | CLI layer: flag parsing, config loading, pipeline orchestration |
| `scanner/` | ~2500 | Core engine: parallel file walk, per-line scanning, pipeline stages, source tech detection |
| `rules/` | ~400 | YAML rule loading, thread-safe compilation, validation |
| `entropy/` | ~300 | Shannon entropy, per-alphabet thresholds, media filter, contextual secrets |
| `decoder/` | ~500 | 9 decoder types + recursive pipeline (depth 3) |
| `finding/` | ~200 | Finding struct, severity enum, dedup, summary building |
| `confidence/` | ~100 | Multi-signal confidence scorer |
| `correlation/` | ~600 | 8 multi-finding correlation detectors |
| `correlator/` | ~200 | SQLite cross-run cache (findings, verdicts, learned weights) |
| `adaptive/` | ~220 | Adaptive confidence learning (Bayesian smoothing, 4 tiers, 90-day decay) |
| `endpoints/` | ~400 | 17 endpoint extraction patterns + 14 risk scoring rules |
| `crawler/` | ~1800 | BFS web crawler, headless Chrome, archive extraction, URL cache, sitemap discovery |
| `jsrecon/` | ~400 | JS string reconstruction (6 methods) + request analysis |
| `json_scanner/` | ~150 | JSON tree-walking scanner |
| `gitscan/` | ~150 | Git commit history walking |
| `formatters/` | ~1400 | 7 output formats + webhook export + summary |
| `validator/` | ~800 | 13 live validation providers + rate limiting |
| `recon/` | ~800 | 11 attack surface detectors (security headers, tech fingerprinting, admin/debug/metrics) |
| `ignore/` | ~100 | .syckignore fingerprint + regex suppression |
| `progress/` | ~80 | TUI progress bar wrapper |
| `ruletest/` | ~300 | Rule quality testing harness |
| `httpclient/` | ~80 | Shared HTTP client factory with proxy, TLS, timeout support |
| `config/` | ~60 | Viper config loading |

---

## 8. Data Flow: End to End

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INPUT DISPATCH                              │
│                                                                     │
│  syck scan [paths]     → filepath.Walk → parallel ScanFile()       │
│  syck scan -u [url]    → crawler.Crawl() BFS → per-URL scanning    │
│  syck scan --pipe      → buffered stdin read → scanContent()        │
│  syck scan --git-history → gitscan.ScanHistory() → per-commit      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       PER-FILE SCANNING                             │
│                                                                     │
│  1. Comment stripping (--strip-comments)                            │
│  2. Regex rule matching (188 rules, all matched per line)             │
│  3. Entropy token scan (context-gated, alphabet-aware thresholds)  │
│  4. Contextual secret extraction (entropy ≥ 4.5, length ≥ 20)     │
│  5. Multi-line pattern matching (--multiline, 10-line window)      │
│  6. Decoder pipeline (9 decoders, recursive depth 3 → rescan)     │
│  7. Auth header detection (--detect-auth-headers)                  │
│  8. URL secret extraction (query parameters)                       │
│                                                                     │
│  Additional per-file passes:                                       │
│  • JSON tree scanning (.json files)                                │
│  • JS string reconstruction (--js-reconstruct)                     │
│  • Endpoint extraction (--endpoints, 17 patterns)                  │
│  • Source technology fingerprinting (--tech-detect)                 │
│  • Package file scanning (npm/yarn/go/cargo)                       │
│  • Binary string extraction (for binary files)                     │
│  • Archive extraction (zip/tar/jar with Zip Slip protection)       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      POST-PROCESSING                                │
│                                                                     │
│  1. Deduplication (context-aware, 40-char prefix)                  │
│  2. FP downgrade (-downgrade-fp: test/mock/vendor + placeholders)  │
│  2b. Apply adaptive modifiers (--adaptive, if enabled)             │
│  3. .syckignore filtering (fingerprint + regex)                    │
│  4. Live validation (--validate, 13 provider APIs)                 │
│  5. SQLite cache recording (--cache-db)                            │
│  5a. Load adaptive weights (--adaptive flag, from SQLite cache)    │
│  6. URL cache recording (--url-cache-db, cross-run URL dedup)      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        OUTPUT                                       │
│                                                                     │
│  Select formatter: text / json / jsonl / sarif / markdown / csv / html │
│  Apply redaction (--redact), color (--no-color)                    │
│  Show adaptive modifier + learning tier (when adaptive enabled)    │
│  Write to file (--output) or stdout                                │
│  Webhook export (--webhook-url: Slack/Discord/JSON)                │
│  CI gate: --fail-on severity → exit 1                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Scanning Modes

### File Scanning (default)
- `filepath.Walk` with skip-directories map (35 entries)
- Extension whitelist: 70+ text file extensions
- Binary detection via null-byte check (first 512 bytes)
- File size limit (default 5MB)
- Parallel dispatch via semaphore (default 10 workers)
- Streaming mode for files > 1MB

### URL Scanning (`--url`)
- BFS with depth tracking (default max depth: 3)
- goquery HTML extraction for link discovery
- Parallel fetching with host-level semaphores
- Cookie jar support with file persistence
- robots.txt compliance (optional)
- Sitemap XML discovery with recursion limits
- Random user-agent rotation (80+ strings)
- Headless Chrome via go-rod for SPAs
- Source map harvesting (.js → .js.map)
- Cloud storage URL detection (S3/GCS/Azure)
- GraphQL introspection probing
- OpenAPI/Swagger spec parsing
- Juicy file probing (65 high-value paths)
- Archive extraction (zip/tar/tar.gz/jar)
- Cross-run URL cache (--url-cache-db, SQLite dedup)
- Security header analysis (--header-check, 18 finding types)
- Technology fingerprinting (--tech-detect, 40+ technologies)

### Stdin Scanning (`--pipe`)
- Buffered read, scan as single content block

### Git History Scanning (`--git-history`)
- `git log --all --format=%H --diff-filter=AM`
- Per-commit file extraction via `git show`
- Per-commit deduplication

---

## 10. Post-Processing Pipeline

### Deduplication
- Key: `ruleName + \x00 + secret + \x00 + file + \x00 + contextPrefix(40chars)`
- Context-aware to avoid merging distinct findings

### FP Downgrade
- Severity-- for test/mock/vendor/example directories
- INFO severity for placeholder patterns (example, changeme, your-key, etc.)

### .syckignore Filtering
- **Fingerprint mode**: SHA256 of `rule:secret:file` — exact-match suppression
- **Pattern mode**: `re:`-prefixed regex matched against secret or file field

### SQLite Cross-Run Cache
- Table: `findings` (fingerprint TEXT PRIMARY KEY, first_seen, last_seen)
- Table: `verdicts` (append-only user feedback: tp/fp per fingerprint)
- Table: `learned_weights` (materialized per-rule+file_pattern learning cache)
- Fingerprint: SHA256 of `ruleName|secret|file`
- Atomic INSERT-or-UPDATE for concurrent access
- Enables progressive triage across scan runs

### URL Cache (`--url-cache-db`)
- Table: `crawled_urls` (url_hash TEXT PRIMARY KEY, url, status_code, content_hash, first_seen, last_seen)
- Cross-run URL dedup: skips previously fetched URLs on subsequent scans
- Content hash enables detecting content changes across runs

---

## 11. Output Formats

| Format | Command | Best For |
|--------|---------|----------|
| Text | `--format text` | Terminal (default, colorized) |
| JSON | `--format json` | Machine parsing, dashboards |
| JSONL | `--format jsonl` | Streaming/piping, one finding per line |
| SARIF | `--format sarif` | GitHub Code Scanning upload |
| Markdown | `--format markdown` | PR comments, reports |
| CSV | `--format csv` | Spreadsheets, data analysis |
| HTML | `--format html` | Browser viewing, dark theme |

### Webhook Export (`--webhook-url`)
- **Slack**: Markdown-formatted messages via incoming webhook
- **Discord**: Embed objects (max 10, color-coded by severity)
- **JSON**: Full findings + summary payload to any HTTP endpoint

---

## 12. Confidence & Risk Scoring

### Confidence Scoring (per finding)

**Signal weights:**
| Signal | Points |
|--------|--------|
| Regex match | +60 |
| High entropy (≥ 4.5) | +15 |
| Context keyword match | +15 |
| Decoded value | +10 |
| URL parameter extraction | +10 |

**Band mapping:**
| Band | Range |
|------|-------|
| LOW | 0-30 |
| MEDIUM | 31-60 |
| HIGH | 61-90 |
| CRITICAL | 91-120 |

### Risk Scoring (per endpoint)

- 14 group-weighted rules in 7 groups
- Per-group max (not flat sum) prevents one category from dominating
- Score: 0-10 integer
- `RequiresAPIPrefix` protection against FPs

### Adaptive Learning

The adaptive learning system learns from user verdicts to adjust confidence scores per rule per file pattern, reducing false positives over time.

**Schema (SQLite, `--cache-db`):**

| Table | Purpose |
|-------|---------|
| `verdicts` | Append-only user feedback (tp/fp per fingerprint) |
| `learned_weights` | Materialized per-rule+file_pattern learning cache |

**Modifier formula:**

1. Bayesian smoothing (prior 5 tp + 5 fp) — prevents extreme adjustments with few samples
2. Base modifier: `(1 − 2 × tp_ratio) × 40` — positive = fewer FPs expected, negative = more FPs expected
3. Minimum evidence ramp-up (0–20 samples) — modifiers scale from 0 to full strength
4. High-certainty rule cap: −10 max for AWS keys, GitHub PATs, Stripe keys, private keys
5. Final clamp: [−40, +40]

**Tiers:**

| Tier | Verdict Count | Meaning |
|------|---------------|---------|
| Experimental | 0–9 | Insufficient evidence for adjustment |
| Learning | 10–49 | Actively learning, moderate confidence |
| Mature | 50–199 | Well-calibrated weights |
| Trusted | 200+ | High-confidence adjustment |

**File pattern extraction:**

| Directory | Pattern |
|-----------|---------|
| `*/test/*` | test |
| `*/mock/*` | mock |
| `*/vendor/*` | vendor |
| `*/node_modules/*` | node_modules |
| `*/example/*` | example |
| Other | file extension |

**Decay:** 90-day exponential half-life — recent verdicts weighted more heavily.

---

## 13. Live Validation

Validate found secrets against provider APIs to confirm they're still active:

| Provider | Rule Names | Method |
|----------|-----------|--------|
| GitHub | github_personal_access_token, github_oauth_access_token | GET /user |
| GitLab | gitlab_personal_token | GET /user |
| Slack | slack_bot_token | GET /auth.test |
| Slack Webhook | slack_webhook_url | POST test payload |
| Stripe | stripe_secret_key, stripe_restricted_key | GET /v1/balance |
| OpenAI | openai_api_key | GET /v1/models |
| OpenAI (org) | openai_org_key | POST /v1/chat/completions |
| Anthropic | anthropic_api_key | POST /v1/messages |
| SendGrid | sendgrid_api_token | GET /v3/user/profile |
| Twilio | twilio_account_sid | GET /Accounts/{sid} |
| npm | npm_token | GET /-/npm/v1/user |
| HuggingFace | huggingface_api_token | GET /api/whoami-v2 |
| AWS | aws_access_key_id | STS GetCallerIdentity |

Unconfirmed secrets are downgraded to `INFO` severity.

---

## 14. External Integrations

| Category | Details |
|----------|---------|
| **Live Validation** | 13 provider APIs (see above) |
| **Webhook Export** | Slack, Discord, generic JSON |
| **SQLite Cache** | Cross-run fingerprinting for progressive triage |
| **URL Cache** | SQLite cross-run URL dedup for crawler |
| **Adaptive Learning** | Bayesian confidence adjustment from user verdicts |
| **GitHub** | SARIF upload (`syck upload-sarif`), Actions workflow, push protection |
| **Headless Chrome** | go-rod for SPA/JS-rendered page scanning |
| **Security Headers** | CSP, HSTS, CORS, cookies, server info — 18 finding types |
| **Tech Fingerprinting** | 40+ technologies from HTTP responses and source code |

---

## 15. CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `syck scan [paths...]` | Main scanning command |
| `syck verdict <fp> tp\|fp` | Record true/false positive verdict for a finding |
| `syck verdict --stats` | View adaptive learning summary |
| `syck list-rules` | List all detection rules |
| `syck ruletest` | Rule quality testing |
| `syck upload-sarif` | Upload SARIF to GitHub Code Scanning |
| `syck version` | Print version, commit, date |
| `syck completion bash` | Generate shell completions |

### Key Flags (67 total)

**Core:** `--severity`, `--format`, `--output`, `--redact`, `--workers`, `--exclude`, `--quiet`, `--no-color`
**Decoders:** `--decode-base64/hex/unicode/url/gzip`, `--js-reconstruct`
**URL:** `--url`, `--crawl-limit/depth`, `--headless`, `--rate-limit`, `--scope`
**Analysis:** `--endpoints`, `--git-history`, `--validate`, `--multiline`, `--strip-comments`, `--scan-archives`, `--scan-binaries`, `--header-check`, `--tech-detect`
**Export:** `--webhook-url/style`, `--cache-db`, `--fail-on`
**Adaptive:** `--adaptive` (enable adaptive learning adjustment on scan)
**Bug Bounty:** `--proxy`, `--auth-token`, `--header`, `--scope-file`, `--cookie`, `--no-sitemap`, `--diff`, `--http-timeout`
**URL Cache:** `--url-cache-db` (SQLite cross-run URL dedup)
**Environment Variables:** Every flag via `SYCK_SCAN_<FLAG>` (uppercase, dashes → underscores)

---

## 16. Rule System

### Rule Schema (YAML)

```yaml
rules:
  - name: my_api_key
    description: "My internal API key"
    severity: CRITICAL
    pattern: 'my_key_[a-zA-Z0-9]{32}'
    tags: [internal, api-key]
    entropy_threshold: 4.5
    context_keywords: [api_key, api-key, API_KEY]
    requires_context: true
    verify: true
    multi_line: false
```

### Rule Categories (188 rules)

| Category | Examples | Count |
|----------|----------|-------|
| Cloud | AWS (5), GCP (5), Azure (3), Alibaba, Hetzner, Scaleway, Linode | 20 |
| VCS | GitHub (5), GitLab (2) | 7 |
| Messaging | Slack (3), Discord (2), Telegram (1) | 6 |
| Payments | Stripe (4), Square (2), PayPal/Braintree (1) | 7 |
| AI Providers | OpenAI (3), Anthropic (2), HuggingFace, Replicate, Groq, etc. | 30+ |
| SaaS | Notion, Linear, Supabase, PlanetScale, ngrok, Cloudflare, etc. | 20+ |
| Infrastructure | Vault, Docker, Kubernetes, Pulumi, CircleCI, Jenkins, Terraform, etc. | 20+ |
| Crypto | RSA/DSA/EC/OpenSSH/PGP/Age private keys | 6 |
| Database | PostgreSQL, MySQL, MongoDB, Redis, SQLite connection strings | 5 |
| Firebase | Service account, Admin SDK, google-services.json | 3 |
| Generic | catch-all patterns for secrets, passwords, tokens, API keys | 10+ |
| Environment | Cloud metadata, .env files, npm auth tokens | 9 |
| PII | email addresses | 1 |
| Password Hashes | bcrypt, SHA256, MD5 | 3 |

### Adding Rules

1. Edit `internal/rules/builtin.yaml`
2. Add positive + negative test fixtures under `internal/ruletest/testdata/`
3. Run `go run . ruletest` to verify precision/recall
4. Run `go test -race ./...` and `go vet ./...`

---

## 17. Testing Strategy

### Test Files: 73 across all packages

| Package | Coverage |
|---------|----------|
| `scanner/` | 14 test files — pipeline stages, URL secrets, auth headers, multiline, binary, strip, entropy, decoder, correlation, verifier, reporter, collector |
| `correlation/` | 11 test files — all 8 detectors + integration |
| `recon/` | 9 test files — all 11 detectors |
| `crawler/` | 8 test files — crawl, extract, archive, juicy, cloud storage, GraphQL, OpenAPI |
| `rules/` | 4 test files — compile, load, validate, matching |
| `decoder/` | 5 test files — registry, pipeline, JWT, base64url, doublebase64 |
| `entropy/` | 2 test files — alphabet, extended entropy |
| `jsrecon/` | 2 test files — reconstruction, analysis |
| `formatters/` | 2 test files — output, webhook |
| `endpoints/` | 2 test files — extraction, risk scoring |
| `ruletest/` | 3 test files — harness, corpus, report |
| Other | 1 test file each |

### CI Commands

```bash
go test -race -timeout 60s ./...   # All tests with race detector
go vet ./...                       # Static analysis
gofmt -l .                         # Format check
golangci-lint run                  # Lint
```

### Rule Quality Testing

```bash
syck ruletest                          # Test all rules
syck ruletest --rule stripe_api_key    # Test specific rule
syck ruletest --fp-threshold 0.5       # Set FP threshold
```

Metrics: precision, recall, FP rate per rule. Status: PASSED / REJECTED / SKIPPED.

---

## 18. Build & Release

### Build

```bash
go build -o syck .                    # Local build
make build                            # Via Makefile
CGO_ENABLED=0 go build -o syck        # Static binary
```

### GoReleaser

- **Targets:** linux/darwin/windows × amd64/arm64
- **Archives:** tar.gz (linux/darwin), zip (windows)
- **Checksums:** SHA256 checksums.txt
- **Changelog:** Auto-generated, excludes docs/chore/test/ci commits
- **ldflags:** Injects version, commit, date into `main.version`

### CI Pipeline

- **Triggers:** push to main, PRs to main
- **Matrix:** ubuntu/macos/windows × Go 1.26.x
- **Steps:** checkout → setup-go → build → gofmt → vet → test -race → lint

### Release Pipeline

- **Triggers:** tag push matching `v*`
- **Steps:** checkout (full history) → setup-go → GoReleaser release

---

## 19. Contributing Guidelines

### Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/syck.git
cd syck
git checkout -b feature/my-rule
```

### Workflow

1. **Pick a task** from the issue tracker or `docs/superpowers/plans/`
2. **Claim it** — change `[ ]` to `[WIP]` in your PR
3. **Read the spec** at `docs/superpowers/specs/`
4. **Write tests first** — every new package needs unit tests
5. **Update checklist** — mark `[x]` when done

### Code Style

- `gofmt` + `go vet` + `go test -race ./...` must all pass
- No new top-level dependencies without discussion
- Package names: lowercase, single word (`confidence`, `correlation`, `recon`)
- Code comments discouraged unless non-obvious (spec docs for rationale)
- Preserve existing `scanner.Config` and CLI flag surface

### Conventions

- New modules: `internal/<module>/` with one package, one test file, one fixture directory
- Fixtures: `internal/<package>/testdata/`
- Temporary scratch: `t.TempDir()`
- YAML rules: add to `internal/rules/builtin.yaml` (extended schema, all new fields optional)

---

## 20. Version History

| Version | Theme | Key Changes |
|---------|-------|-------------|
| V1.0 | Foundation | Rule schema, entropy helpers, confidence scoring, pipeline refactor |
| V1.1 | Decoding & Correlation | JWT/double-base64 decoders, 8 correlation detectors |
| V1.2 | JS / Source Maps / Frontend | JS reconstruction (6 methods), endpoint extraction (21+ patterns), risk scoring |
| V1.3 | URL Secrets & Confidence | URL param extraction, contextual entropy, confidence scoring (0-100) |
| V1.4 | JS Ternary Extraction | Ternary expression extraction from `condition ? "A" : "B"` |
| V1.5+ | Crawling + Scanning | BFS crawler, headless Chrome, archive scanning, binary extraction, webhook export, SQLite cache |
| V1.6 | Code Reviews | 3 rounds of review (Zip Slip, OOB bounds, dead code cleanup, performance) |
| V1.7 | Operational Polish | Env var config, TUI progress, SARIF upload |

### V1.8 — Bug Bounty Core

- Bug bounty flags (proxy, auth-token, header, scope-file, cookie, no-sitemap, diff, http-timeout)
- Shared HTTP client factory (proxy, TLS, timeout support)
- Sitemap XML discovery with recursion limits
- JSONL/NDJSON output format
- Diff mode (--diff, only new findings)
- Cookie parser and header transport
- 9 new detection rules (cloud metadata, env secrets, age, twilio, cloudflare, firebase, terraform, supabase, alibaba, hetzner, scaleway, linode)

### V1.9 — Security Headers & Tech Fingerprinting

- Security header analysis (18 finding types: CSP, HSTS, CORS, cookies, XCTO, Referrer-Policy, Permissions-Policy, server info, security.txt)
- Web technology fingerprinting (40+ technologies from HTTP headers, body, cookies)
- Source code technology fingerprinting (package manifests, config files, imports)
- --header-check and --tech-detect CLI flags (both default: true)
- 188 total detection rules

---

## Quick Reference for AI Agents

When working on this codebase:

1. **CI commands**: `go test -race ./...`, `go vet ./...`, `gofmt -l .`
2. **Working binary**: `/home/raven/go/bin/syck`
3. **Module path**: `github.com/RA000WL/syck`
4. **Go version**: 1.26+
5. **Rules file**: `internal/rules/builtin.yaml`
6. **Entry point**: `main.go` → `cmd.Execute()`
7. **Core scanning**: `internal/scanner/scan.go` (ScanPaths, ScanContent, etc.)
8. **Output**: 7 formats via `internal/formatters/` (text, json, jsonl, sarif, markdown, csv, html)
9. **Never assume libraries** — check `go.mod` and neighboring files first
10. **Run tests after every change** — `go test -race ./...`
