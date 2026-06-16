# SYCK Architecture Reference

> Living document for contributors, AI agents, and future maintainers. Covers design decisions, data flow, key interfaces, and package responsibilities.

---

## Table of Contents

1. [Project Identity](#1-project-identity)
2. [Design Philosophy](#2-design-philosophy)
3. [Directory Layout](#3-directory-layout)
4. [Core Pipeline](#4-core-pipeline)
5. [Detection Engine (10 Layers)](#5-detection-engine-10-layers)
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
19. [Performance Optimizations](#19-performance-optimizations)
20. [Version History](#20-version-history)

---

## 1. Project Identity

| Attribute | Value |
|-----------|-------|
| Name | **SYCK** (SecretsYouCantKeep) |
| Language | Go 1.26+ |
| Module Path | `github.com/RA000WL/syck` |
| License | MIT |
| Current Version | 1.2.0 (V1.3+ features on main) |
| Binary | Single static binary, zero runtime dependencies |
| Purpose | Detect hardcoded secrets, API keys, tokens, passwords, and credentials in source code, configs, web pages, and binaries |

### What Makes It Different

Most scanners fall into two camps:
- **Regex-only** (gitleaks): misses obfuscated/encoded secrets
- **Entropy-only** (trufflehog): drowns users in false positives

SYCK combines both with context keywords, multi-layer decoding, JS string reconstruction, JavaScript analysis, endpoint extraction, subdomain discovery, live validation, and confidence scoring into a unified pipeline.

---

## 2. Design Philosophy

1. **Layered detection** — no single technique catches everything. Regex, entropy, context, decoding, and reconstruction are stacked.
2. **Recursive decoding** — secrets hidden in base64, hex, JWT, etc. are decoded and re-scanned up to depth 3.
3. **JS-aware analysis** — JavaScript string obfuscation (concat, join, template literals, ternaries) is reversed before scanning.
4. **Recon-first approach** — subdomain discovery, endpoint extraction, and internal link detection complement secret scanning.
5. **Confidence over severity** — severity is what the rule says; confidence is how sure we are. Both live on every Finding.
6. **Progressive triage** — SQLite cache enables cross-run dedup so teams can focus on new findings.
7. **Zero-config defaults** — works out of the box; every behavior is tunable via 60+ flags.

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
│   ├── recon.go                    # Recon command — subdomain discovery
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
│   │   ├── builtin.yaml            # 200+ embedded rules
│   │   ├── rule.go                 # Rule/RuleSet types, matching
│   │   ├── load.go                 # YAML loading, embedding, RuleLoader
│   │   ├── compile.go              # Thread-safe regex compilation cache
│   │   └── validate.go             # Rule validation (names, severities, duplicates)
│   │
│   ├── scanner/                    # Core scanning engine
│   │   ├── scanner.go              # Config struct (60+ fields)
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
│   │   ├── extract.go              # 30+ regex patterns (API versioning, REST, GraphQL, gRPC, webhooks, internal)
│   │   └── risk.go                 # Risk scoring rules
│   │
│   ├── jsanalysis/                 # JavaScript/Source analysis (NEW)
│   │   └── analyze.go              # Environment variables, secrets, internal URLs, debug artifacts, sensitive files
│   │
│   ├── discovery/                  # Subdomain discovery
│   │   ├── subdomain.go            # crt.sh + CertSpotter CT logs + DNS bruteforce
│   │   ├── dns.go                  # DNS resolution
│   │   ├── hostcheck.go            # Live host checking
│   │   └── wayback.go              # Wayback Machine URL fetching
│   │
│   ├── crawler/                    # Web crawling
│   │   ├── crawler.go              # BFS crawler with parallel fetching + connection pooling
│   │   ├── extract.go              # URL extraction from HTML (goquery)
│   │   ├── parallel.go             # Host-semaphore concurrency control
│   │   ├── headless.go             # Headless Chrome (go-rod)
│   │   ├── cookies.go              # Cookie jar persistence
│   │   ├── robots.go               # robots.txt parsing
│   │   ├── useragent.go            # Random user-agent rotation (80+ strings)
│   │   ├── encoding.go             # Character encoding detection + body pooling
│   │   ├── juicy.go                # High-value path probing (150+ paths)
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
│   │   ├── text.go                 # Colorized terminal (professional format with icons)
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
│   │   ├── detector_internal.go    # Enhanced internal link detection (private IPs, cloud metadata, K8s/Docker)
│   │   └── detector_*.go           # 12 detectors (admin, auth, debug, graphql, headers, internal, metrics, staging, storage, swagger, techweb, waf)
│   │
│   ├── ignore/                     # .syckignore support
│   │   └── ignore.go               # Fingerprint + regex pattern suppression
│   │
│   ├── progress/                   # TUI progress bar
│   │   └── progress.go             # schollz/progressbar wrapper
│   │
│   ├── ruletest/                   # Rule quality testing
│   │   ├── harness.go              # Test harness (precision/recall/FP rate)
│   │   ├── report.go               # Test reporting
│   │   ├── corpus.go               # Positive/negative corpus loading
│   │   └── generate.go             # Corpus generation utilities
│   │
│   └── httpclient/                 # Shared HTTP client factory
│       └── client.go               # Transport + client with connection pooling, proxy, TLS support
│
├── docs/                           # Design docs and specs
│   ├── examples/
│   │   └── github-actions.yml      # Example CI workflow
│   └── superpowers/                # Design specs and implementation plans
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

### Active Execution Path

The CLI uses the V6 inline orchestration path:

```
cmd/scan.go
  │
  ├── File paths  → scanner.ScanPaths()  → filepath.Walk + parallel ScanFile()
  ├── URLs        → scanner.ScanURLs()   → crawler.Crawl() BFS + per-URL scanning
  ├── Stdin       → scanner.ScanReader() → auto-detect URLs vs raw content
  └── Git history → gitscan.ScanHistory() → git log/show per-commit
```

---

## 5. Detection Engine (10 Layers)

SYCK uses a **multi-layer detection approach** where each layer catches different types of secrets:

### Layer 1: Regex Pattern Matching
- **200+ rules** in `internal/rules/builtin.yaml`
- Each rule: name, severity, regex pattern, tags, optional entropy threshold, context keywords
- Compiled once at startup with thread-safe caching
- Context gating enforced: rules with `requires_context: true` only fire when the line contains one of their `context_keywords`

### Layer 2: Entropy Analysis
- Shannon entropy calculation
- Context-gated: only fires on lines containing secret-related keywords
- Per-alphabet thresholds: hex ≥ 3.0, base64/JWT ≥ 4.0, unknown ≥ 4.5
- Media token filtering: detects 15 base64-encoded media formats to avoid FPs

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

### Layer 6: JSON-Aware Scanning
- Parses JSON files and walks the tree
- Matches values under keys matching 30+ secret-key patterns

### Layer 7: URL Secret Extraction
- Parses URLs found in source code
- Extracts secrets from query parameters: access_token, token, api_key, auth, jwt, bearer, key, secret

### Layer 8: Auth Header Detection
- Bearer token patterns
- Basic auth patterns
- API key header patterns

### Layer 9: Binary String Extraction
- Extracts printable UTF-8 strings ≥ 8 bytes from binary files
- Scans extracted strings through the normal detection pipeline

### Layer 10: JavaScript/Source Analysis (NEW)
- Environment variable detection (`process.env.*`, `import.meta.env.*`)
- Dynamic import extraction (`import()`, `require()`)
- Hidden secret detection (config secrets, base64 encoded values, TODO/FIXME leaks)
- Internal URL detection (localhost, private IPs, cloud metadata)
- Debug artifact detection
- Sensitive file references (`.env`, `.key`, `.pem`, credentials)

---

## 6. Key Types & Interfaces

### Finding (`internal/finding/finding.go`)

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
    IsNew                          bool
    AdaptiveModifier               int       // -40 to +40
    LearningTier                   string    // Experimental/Learning/Mature/Trusted
}
```

### JSAnalysisResult (`internal/jsanalysis/analyze.go`)

```go
type JSAnalysisResult struct {
    EnvVars         []string
    Endpoints       []string
    Secrets         []SecretFinding
    InternalURLs    []string
    DebugArtifacts  []string
    SourceMaps      []string
    SensitiveFiles  []string
    Chunks          []string
    LeakedComments  []string
}
```

### Recon Detector (`internal/recon/recon.go`)

```go
type Detector interface {
    Detect(urls []string) []SurfaceFinding
}
// 12 implementations: Admin, Auth, Debug, GraphQL, Headers, Internal,
// Metrics, Staging, Storage, Swagger, TechFingerprintWeb, WAF
```

---

## 7. Package Map

| Package | Responsibility |
|---------|----------------|
| `cmd/` | CLI layer: flag parsing, config loading, pipeline orchestration |
| `scanner/` | Core engine: parallel file walk, per-line scanning, pipeline stages |
| `rules/` | YAML rule loading, thread-safe compilation, validation |
| `entropy/` | Shannon entropy, per-alphabet thresholds, media filter |
| `decoder/` | 9 decoder types + recursive pipeline (depth 3) |
| `finding/` | Finding struct, severity enum, dedup, summary building |
| `confidence/` | Multi-signal confidence scorer |
| `correlation/` | 8 multi-finding correlation detectors |
| `correlator/` | SQLite cross-run cache |
| `adaptive/` | Adaptive confidence learning |
| `endpoints/` | 30+ endpoint extraction patterns + risk scoring |
| `jsanalysis/` | JavaScript/source analysis (env vars, secrets, internal URLs) |
| `discovery/` | Subdomain enumeration (crt.sh, CertSpotter, DNS bruteforce) |
| `crawler/` | BFS web crawler, headless Chrome, archive extraction, body pooling |
| `jsrecon/` | JS string reconstruction (6 methods) + request analysis |
| `json_scanner/` | JSON tree-walking scanner |
| `gitscan/` | Git commit history walking |
| `formatters/` | 7 output formats + webhook export |
| `validator/` | 13 live validation providers + rate limiting |
| `recon/` | 12 attack surface detectors |
| `ignore/` | .syckignore fingerprint + regex suppression |
| `progress/` | TUI progress bar wrapper |
| `ruletest/` | Rule quality testing harness |
| `httpclient/` | Shared HTTP client with connection pooling |

---

## 8. Data Flow: End to End

```
┌─────────────────────────────────────────────────────────────────────┐
│                         INPUT DISPATCH                              │
│                                                                     │
│  syck scan [paths]     → filepath.Walk → parallel ScanFile()       │
│  syck scan -u [url]    → crawler.Crawl() BFS → per-URL scanning    │
│  syck scan --pipe      → auto-detect URLs vs raw content           │
│  syck scan --git-history → gitscan.ScanHistory() → per-commit      │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       PER-FILE SCANNING                             │
│                                                                     │
│  1. Comment stripping (--strip-comments)                            │
│  2. Regex rule matching (200+ rules)                                 │
│  3. Entropy token scan (context-gated, alphabet-aware)             │
│  4. Contextual secret extraction (entropy ≥ 4.5, length ≥ 20)     │
│  5. Multi-line pattern matching (--multiline, 10-line window)      │
│  6. Decoder pipeline (9 decoders, recursive depth 3 → rescan)     │
│  7. Auth header detection                                           │
│  8. URL secret extraction                                           │
│  9. JS/Source analysis (env vars, secrets, internal URLs)          │
│                                                                     │
│  Additional per-file passes:                                       │
│  • JSON tree scanning (.json files)                                │
│  • JS string reconstruction (--js-reconstruct)                     │
│  • Endpoint extraction (--endpoints, 30+ patterns)                 │
│  • Source technology fingerprinting (--tech-detect)                 │
│  • Package file scanning                                           │
│  • Binary string extraction                                        │
│  • Archive extraction (zip/tar/jar with Zip Slip protection)       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      POST-PROCESSING                                │
│                                                                     │
│  1. Deduplication                                                  │
│  2. FP downgrade                                                   │
│  3. .syckignore filtering                                          │
│  4. Live validation (--validate, 13 provider APIs)                 │
│  5. SQLite cache recording                                         │
│  6. Adaptive learning (--adaptive)                                 │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        OUTPUT                                       │
│                                                                     │
│  Select formatter: text / json / jsonl / sarif / markdown / csv / html │
│  Apply redaction, color, professional formatting                   │
│  Write to file or stdout                                           │
│  Webhook export (Slack/Discord/JSON)                               │
│  CI gate: --fail-on severity → exit 1                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Scanning Modes

### File Scanning (default)
- `filepath.Walk` with skip-directories map (35 entries)
- Extension whitelist: 70+ text file extensions
- Parallel dispatch via semaphore (default 10 workers)
- Streaming mode for files > 1MB

### URL Scanning (`--url`)
- BFS with depth tracking (default max depth: 3)
- goquery HTML extraction for link discovery
- Parallel fetching with host-level semaphores
- Cookie jar support with file persistence
- robots.txt compliance (optional)
- Sitemap XML discovery
- Random user-agent rotation (80+ strings)
- Headless Chrome via go-rod for SPAs
- Source map harvesting (.js → .js.map)
- Cloud storage URL detection (S3/GCS/Azure)
- GraphQL introspection probing
- OpenAPI/Swagger spec parsing
- Juicy file probing (150+ paths including .well-known, source maps, actuator)
- Security header analysis (--header-check)
- Technology fingerprinting (--tech-detect)
- WAF/CDN detection

### Stdin Scanning (`--pipe`)
- **Auto-detects URLs vs raw content**
- URLs: fetches and scans each URL
- Raw content: scans as text block

### Git History Scanning (`--git-history`)
- `git log --all --format=%H --diff-filter=AM`
- Per-commit file extraction via `git show`

---

## 10. Output Formats

| Format | Command | Best For |
|--------|---------|----------|
| Text | `--format text` | Terminal (default, professional with severity icons) |
| JSON | `--format json` | Machine parsing, dashboards |
| JSONL | `--format jsonl` | Streaming/piping, one finding per line |
| SARIF | `--format sarif` | GitHub Code Scanning upload |
| Markdown | `--format markdown` | PR comments, reports |
| CSV | `--format csv` | Spreadsheets, data analysis |
| HTML | `--format html` | Browser viewing, dark theme |

---

## 11. Performance Optimizations

### HTTP Client (`internal/httpclient/client.go`)
- **Connection pooling**: MaxIdleConns=200, MaxIdleConnsPerHost=50
- **Keep-alive**: Enabled by default, 120s idle timeout
- **Compression**: Enabled gzip/deflate
- **Buffer sizes**: 64KB read/write buffers
- **TLS**: Min version TLS 1.2, max TLS 1.3

### Crawler (`internal/crawler/`)
- **Body pooling**: Reuses response buffers via `sync.Pool`
- **Pre-allocated buffers**: 64KB initial capacity, grows dynamically
- **Connection headers**: Keep-alive explicitly set
- **10MB read limit**: Prevents memory exhaustion

### Transport Pool
- **Reusable transports**: `TransportPool` for concurrent operations

---

## 12. Version History

| Version | Theme | Key Changes |
|---------|-------|-------------|
| V1.0 | Foundation | Rule schema, entropy helpers, confidence scoring |
| V1.1 | Decoding & Correlation | JWT/double-base64 decoders, 8 correlation detectors |
| V1.2 | JS / Source Maps | JS reconstruction, endpoint extraction (21+ patterns), risk scoring |
| V1.3 | URL Secrets | URL param extraction, contextual entropy, confidence scoring |
| V1.5+ | Crawling + Scanning | BFS crawler, headless Chrome, archive scanning, webhook export |
| V1.8 | Bug Bounty Core | Proxy, auth-token, header, scope-file, cookie, diff mode |
| V1.9 | Security Headers | 18 finding types, 40+ tech fingerprinting, 188 rules |
| V2.0 | Recon Optimization | jsanalysis, enhanced endpoints (30+), CertSpotter, DNS bruteforce, 150+ juicy paths, internal link detection, professional output, pipe mode fix, performance optimizations |

---

## Quick Reference for AI Agents

When working on this codebase:

1. **CI commands**: `go test -race ./...`, `go vet ./...`, `gofmt -l .`
2. **Module path**: `github.com/RA000WL/syck`
3. **Go version**: 1.26+
4. **Rules file**: `internal/rules/builtin.yaml`
5. **Entry point**: `main.go` → `cmd.Execute()`
6. **Core scanning**: `internal/scanner/scan.go`
7. **JS analysis**: `internal/jsanalysis/analyze.go`
8. **Subdomain discovery**: `internal/discovery/subdomain.go`
9. **Output**: 7 formats via `internal/formatters/`
10. **Run tests after every change** — `go test -race ./...`
