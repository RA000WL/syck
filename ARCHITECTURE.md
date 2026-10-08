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
12. [Performance Optimizations](#12-performance-optimizations)
13. [Version History](#13-version-history)
14. [Testing Strategy](#14-testing-strategy)

---

## 1. Project Identity

| Attribute | Value |
|-----------|-------|
| Name | **SYCK** (SecretsYouCantKeep) |
| Language | Go 1.26+ |
| Module Path | `github.com/RA000WL/syck` |
| License | MIT |
| Current Version | 1.2.0 (V1.3+ features on main, 199 rules) |
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
5. **Confidence over severity** — severity is what the rule says; confidence is how sure we are. Both live on every secret Finding (endpoints/juicy-files/internal-URL/debug-artifact findings carry neither).
6. **Progressive triage** — SQLite cache enables cross-run dedup so teams can focus on new findings.
7. **Zero-config defaults** — works out of the box; every behavior is tunable via 60+ flags.
8. **Cross-rule dedup** — a secret triggering multiple rules keeps one finding per occurrence; the highest-severity rule stays primary in `RuleName` and the others are listed in `RuleNames`.
9. **Aggressive FP elimination** — sorted alphabet detection, base58 filtering, image filename FPs, placeholder tokens.

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
│   ├── scan_config.go              # scanCmd, the flag block + init() registration, clampWorkers/parseSize/loadWordlist/parseExcludeDir
│   ├── scan_run.go                 # runScan — mode dispatch and pipeline orchestration
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
│   │   ├── builtin.yaml            # 199 embedded rules
│   │   ├── rule.go                 # Rule/RuleSet types, matching
│   │   ├── load.go                 # YAML loading, embedding, RuleLoader
│   │   ├── compile.go              # Thread-safe regex compilation cache
│   │   └── validate.go             # Rule validation (names, severities, duplicates)
│   │
│   ├── scanner/                    # Core scanning engine
│   │   ├── scanner.go              # Config struct (60+ fields)
│   │   ├── scan_paths.go           # ScanPaths — parallel file walk, worker pool, dedup
│   │   ├── scan_file.go            # ScanFile / ScanBinaryFile — per-file entry points
│   │   ├── scan_content.go         # ScanContent — in-memory string scanning
│   │   ├── scan_read.go            # ScanReader — stdin/file stream entry point
│   │   ├── scan_stream.go          # Streaming scan path + whole-file fallback
│   │   ├── scan_urls.go            # ScanURLs — crawl + per-URL scanning
│   │   ├── scan_util.go            # Shared scan helpers (text detect, skip dirs, JWT expiry, new-only filter)
│   │   ├── helpers.go              # Per-line scan helpers + URL/crawl/recon analyzers
│   │   ├── pipeline.go             # Pipeline type (8 typed stages) — test-only, not on the CLI path
│   │   ├── stage_*.go              # Individual pipeline stages — test-only, not on the CLI path
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
│   ├── sqliteutil/                 # Shared SQLite open tuning (Batch 4d)
│   │   └── sqliteutil.go           # Open — single-writer cap (SetMaxOpenConns(1)), WAL, busy_timeout=5000. Two consumers: correlator/ and crawler/urlcache.go. Pragmas are best-effort; a pragma failure never fails the open
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
│   │   ├── encoding.go             # Character encoding detection (Content-Type, meta, BOM)
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
│   ├── netguard/                   # SSRF gate for secondary fetches (Batch 1)
│   │   └── netguard.go             # THE copy of the private/loopback/link-local CIDR list + metadata host. IsPrivateIP (RFC 1918), IsBlockedIP (private + loopback + link-local + unspecified, delegates to IsPrivateIP), IsMetadataHost, AllowFetch, ParseHostIP (the ONE host→address resolver: AllowFetch and internalurl both call it). Literal IPs only — no DNS resolution
│   │
│   ├── internalurl/                # "Is this URL internal?" predicates (Batch 4c)
│   │   └── internalurl.go          # IsPrivateHost/IsLoopback/IsCloudMetadata (parsed host via netguard.ParseHostIP, delegate CIDR to netguard) + IsInternalHost/IsInternalPath/IsSensitivePort (raw text). One caller: recon's classifyInternal. No DNS resolution
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
cmd/scan_run.go
  │
  ├── File paths  → scanner.ScanPaths()  → filepath.Walk + parallel ScanFile()
  ├── URLs        → scanner.ScanURLs()   → crawler.Crawl() BFS + per-URL scanning
  ├── Stdin/pipe  → scanner.ScanContent() (raw content) or scanner.ScanURLs() (piped URLs)
  └── Git history → gitscan.ScanHistory() → git log/show per-commit
```

The `Pipeline` type and the `stage_*.go` types (`internal/scanner/pipeline.go`)
are a separate staged decomposition of the same work. They are not on the path
above: `NewPipeline` is called only from `pipeline_test.go`, and no stage
constructor has a non-test caller outside `NewPipeline`. See the
`internal/scanner` package doc for what the stages cover that this path does not.

---

## 5. Detection Engine (10 Layers)

SYCK uses a **multi-layer detection approach** where each layer catches different types of secrets:

### Layer 1: Regex Pattern Matching
- **199 rules** in `internal/rules/builtin.yaml`
- Each rule: name, severity, regex pattern, tags, optional entropy threshold, context keywords
- Compiled once at startup with thread-safe caching
- Context gating enforced: rules with `requires_context: true` only fire when the line contains one of their `context_keywords`

### Layer 2: Entropy Analysis
- Shannon entropy calculation
- Context-gated: only fires on lines containing secret-related keywords
- Per-alphabet thresholds: hex ≥ 3.0, base64/JWT ≥ 4.0, unknown ≥ 4.5
- Media token filtering: detects 15 base64-encoded media formats to avoid FPs
- Sorted sequence detection: catches alphabet/charset listings (ascending ASCII, 30+ chars)
- Trailing camelCase variable name filtering

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

### Layer 11: JWT Expiry Detection
- Decodes JWT payload and checks `exp` claim against `time.Now()`
- Creates HIGH severity finding for expired tokens (rule: `expired_jwt_token`)
- Wired into both streaming and non-streaming scan paths

### Layer 12: Terraform State Detection
- Detects sensitive values in `.tfstate` files via `"value": "..."` patterns
- Requires context gating (keywords: sensitive, attributes, resources)
- CRITICAL severity for secrets in state files

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
    Confidence                     int       // 0-120 numeric
    ConfidenceBand                 string    // LOW/MEDIUM/HIGH/CRITICAL
    DetectionMethod                string    // regex/entropy/context/decoded/url_param
    VerificationStatus             string    // VERIFIED/LIKELY/POTENTIAL/UNVERIFIED
    IsNew                          bool
    AdaptiveModifier               int       // -40 to +40
    LearningTier                   string    // Experimental/Learning/Mature/Trusted
}

// Deduplication: DeduplicateBySecret emits one finding per occurrence
// (Secret+File group, split by File+Line+Column). RuleName is a single exact
// rule name — the highest-severity rule at that occurrence — and RuleNames
// lists every rule that matched it (severity desc, then name asc). Rule names
// are never joined into one string.
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
| `cmd/` | CLI layer: flag parsing (`scan_config.go`), config loading, pipeline orchestration (`scan_run.go`) |
| `scanner/` | Core engine: parallel file walk (`scan_paths.go`), per-file/content/reader entry points (`scan_file.go`, `scan_content.go`, `scan_read.go`), URL scanning (`scan_urls.go`), streaming (`scan_stream.go`), shared helpers (`scan_util.go`, `helpers.go`), goroutine workers, pipeline stages |
| `rules/` | YAML rule loading, thread-safe compilation, validation |
| `entropy/` | Shannon entropy, per-alphabet thresholds, media filter |
| `decoder/` | 9 decoder types + recursive pipeline (depth 3) |
| `finding/` | Finding struct, severity enum, dedup, summary building |
| `confidence/` | Multi-signal confidence scorer |
| `correlation/` | 8 multi-finding correlation detectors |
| `correlator/` | SQLite cross-run cache + file mtime cache for incremental scanning |
| `sqliteutil/` | Shared SQLite open tuning: single-writer cap, WAL, busy timeout |
| `netguard/` | SSRF gate for secondary fetches; literal private/loopback/link-local IPs and the cloud metadata hostname are denied (no DNS resolution). Also owns `ParseHostIP`, the one host→address resolver, which `internalurl` shares |
| `internalurl/` | Single home for the internal/private-URL vocabulary: private host, loopback, cloud metadata, internal host, internal path, sensitive service port |
| `adaptive/` | Adaptive confidence learning |
| `endpoints/` | 30+ endpoint extraction patterns + risk scoring |
| `jsanalysis/` | JavaScript/source analysis (env vars, secrets, internal URLs) |
| `discovery/` | Subdomain enumeration (crt.sh, CertSpotter, DNS bruteforce) |
| `crawler/` | BFS web crawler, headless Chrome, archive extraction |
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
| `fileutil/` | File extension detection and text file identification |
| `parambrute/` | Hidden parameter brute-force discovery |
| `sourcemap/` | JavaScript source map parsing and secret extraction |
| `lsp/` | Language server protocol integration |
| `externaltools/` | Integration with external security tools (tool discovery, version checks, output parsing) |

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
│  2. Regex rule matching (199 rules, parallel workers)              │
│  3. Entropy token scan (context-gated, alphabet-aware)             │
│  4. Contextual secret extraction (entropy ≥ 4.5, length ≥ 20)     │
│  5. Multi-line pattern matching (--multiline, 10-line window)      │
│  6. Decoder pipeline (9 decoders, recursive depth 3 → rescan)     │
│  7. Auth header detection                                           │
│  8. URL secret extraction                                           │
│  9. JWT expiry detection                                            │
│  10. JS/Source analysis (env vars, secrets, internal URLs)         │
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
│  POST-PROCESSING                                │
│                                                                     │
│  1. Cross-rule dedup (by secret value, keep highest severity)      │
│  2. Deduplication (exact match)                                     │
│  3. FP downgrade + false positive filters (sorted seq, base58,     │
│     image filenames, placeholder tokens)                            │
│  4. .syckignore filtering                                          │
│  5. Mtime skip cache (--cache-db incremental)                      │
│  6. Live validation (--validate, 13 provider APIs)                 │
│  7. SQLite cache recording                                         │
│  8. Adaptive learning (--adaptive)                                 │
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
- `filepath.Walk` with skip-directories map (35 entries) + `--exclude-dir` regex
- Extension whitelist: 70+ text file extensions
- Parallel dispatch via semaphore (default 10 workers)
- Streaming mode for files > 1MB with 10MB buffer
- Mtime-based skip cache for incremental scanning

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

## 10. Post-Processing Pipeline

Raw detection output runs through these stages before formatting
(`internal/finding`, `internal/scanner/downgrade.go`, `internal/correlator`,
`internal/adaptive`):

```
raw findings
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DEDUP                                                            │
│                                                                     │
│  1. Deduplicate (exact match)                                      │
│     key: RuleName + Secret + File + 40-char context prefix         │
│                                                                     │
│  2. DeduplicateBySecret (cross-rule, by secret value)              │
│     groups by Secret + File, then buckets by Line + Column         │
│     → ONE FINDING PER OCCURRENCE (line info preserved)             │
│     → RuleName   = single highest-severity rule at that occurrence  │
│     → RuleNames  = all rules that matched, severity desc then name  │
│     → Severity   = highest within the occurrence bucket            │
│     RuleName stays a single exact name: correlation detectors       │
│     (8 detectors, exact match) and adaptive weights are keyed on it.│
│                                                                     │
│  Bypass with --no-dedup.                                            │
└─────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  FILTERING                                                         │
│                                                                     │
│  3. FP downgrade (test/mock/vendor dirs, placeholder patterns)      │
│  4. .syckignore fingerprint suppression                             │
│  5. Mtime skip cache (--cache-db incremental scans)                │
└─────────────────────────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────────────────┐
│  SCORING                                                           │
│                                                                     │
│  6. Confidence — single unified scale (internal/confidence),        │
│     0–120 points, every secret finding carries Confidence +        │
│     ConfidenceBand (endpoints/juicy/internal-url do not)           │
│       regex/decoded/expired-JWT match ......... 40  (PtsRegex)     │
│       entropy + context keyword ................. 35  (20 + 15)     │
│       URL query-param secret .................. 55  (40 + 15)     │
│       live-verified secret .................... +50                │
│       credential pair .......................... +30                │
│     Bands: <=30 LOW · <=60 MEDIUM · <=90 HIGH · <=120 CRITICAL     │
│                                                                     │
│  7. SQLite cache recording (--cache-db): fingerprint =              │
│     sha256(RuleName | Secret | File), first/last seen, IsNew        │
│     (feeds --diff)                                                 │
│                                                                     │
│  8. Adaptive learning (--adaptive): Bayesian-smoothed per           │
│     (RuleName, filePattern) modifier, clamped [-40, +40];           │
│     high-certainty rules capped at -10                             │
└─────────────────────────────────────────────────────────────────────┘
     │
     ▼
formatter → stdout / file / webhook
```

**Note on counts:** because dedup is per-occurrence rather than per-secret,
one secret matched by N rules in one file yields N findings rather than 1.
This is intentional — it restores line-level triage signal that the previous
per-secret collapse destroyed.

---

## 11. Output Formats

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

## 12. Performance Optimizations

### Parallel Rule Matching
- `scanLineForRegexRules` partitions rules across `NumCPU` goroutine workers
- Each worker processes a chunk of rules concurrently against the same line
- Falls back to sequential for <64 rules or single CPU
- Thread-safe: rules are read-only, findings collected per-worker then merged

### Mtime-Based Skip Cache
- SQLite `file_mtimes` table stores `file_path → mtime` mapping
- `ShouldSkipFile(path, mtime)` returns true if file hasn't changed
- `RecordFileMtime(path, mtime)` updates after scan
- Enables incremental scanning — only scan modified files

### Streaming Buffer
- 10MB buffer for streaming scanner (handles minified JS mega-lines)
- `scanFileFallback` handles `bufio.ErrTooLong` gracefully

### HTTP Client (`internal/httpclient/client.go`)
- **Connection pooling**: MaxIdleConns=200, MaxIdleConnsPerHost=50
- **Keep-alive**: Enabled by default, 120s idle timeout
- **Compression**: Enabled gzip/deflate
- **Buffer sizes**: 64KB read/write buffers
- **TLS**: Min version TLS 1.2, max TLS 1.3

### Crawler (`internal/crawler/`)
- **Bounded reads**: Bodies read through `io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))` with a 10MB hard cap, preventing memory exhaustion; the read buffer is allocated per call and is not pooled (see §15 item 5)
- **Connection headers**: Keep-alive explicitly set

### Transport Pool
- **Reusable transports**: `TransportPool` for concurrent operations

---

## 13. Version History

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
| V2.1 | Accuracy & Performance | Cross-rule dedup by secret value, bare-token FP filter (sorted alphabet, base58, placeholders), email FP fix, parallel rule matching (goroutine worker pool), mtime-based skip cache, --exclude-dir flag, streaming progress indicator |
| V2.2 | Detection Expansion | aws_session_token_long (ASIA... 48+), JWT expiry detection (IsJWTExpired/ScanExpiredJWTs), terraform_state_secret, kubernetes kubeconfig (3 rules), GitHub Actions secrets (2 rules) |
| 1.2.0 | Batch 1 — Hardening | Validator TLS verification on, same-origin-only credential forwarding, `internal/netguard` SSRF gate (+`--allow-private-ips`), webhook redaction + HTTPS default (+`--allow-insecure-webhook`), bounded gzip/archive reads, crawler visited-map race fix, `SYCK_SCAN_*` env binding with CLI precedence, `--workers` clamp, repo-wide gofmt |
| 2.0.0 | Batch 2 — Detection Quality | All 9 decoders reachable via 4 new default-off flags, mixed-case hex + JWT decode-order fixes, decoded-scan truncation removed, recursion fan-out bound, per-rule `entropy_threshold` enforced in regex + decoded paths, 16 rules tightened/gated, `openai_legacy_key` + `slack_user_token` added, 5 subsumed dupes removed (202→199), severity normalization, per-occurrence dedup with `RuleNames` attribution, unified confidence scale, adaptive high-certainty names refreshed |

---

## 14. Testing Strategy

```bash
# Run all tests with race detector
go test -race ./...

# Run specific package tests
go test -race ./internal/scanner/ -v
go test -race ./internal/entropy/ -v

# Run rule quality tests
syck ruletest
```

### Test Coverage by Package
| Package | Coverage | Tests |
|---------|----------|-------|
| `fileutil` | 100% | 88 tests (extensions, IsTextExt, edge cases) |
| `jsanalysis` | 98.7% | 38 tests (env vars, imports, secrets, config URLs) |
| `sourcemap` | 95.6% | 45 tests (VLQ, parsing, extraction, truncation) |
| `parambrute` | 86.4% | 38 tests (rate limiter, brute force, isInteresting) |
| `scanner` | — | Streaming tests: mega-line, ErrTooLong fallback, standard file |
| `correlator` | — | Mtime cache tests: ShouldSkipFile, RecordFileMtime |

---

## 15. Known Defects (Deferred)

Items 3, 5, 6, 8 and 9 below remain open, plus the residual link-local asymmetry recorded under item 9. **The
numbering is deliberately left uncompacted**: items 1 and 2 were fixed in Batch
6 and removed, and their numbers are kept as gaps so that existing
cross-references (`§15 item 1`) stay resolvable rather than silently
repointing at a different defect. Item 4 and item 10 are CLOSED entries kept
for the same reason. Item 7 is CLOSED by Batch 9, but not empty: it carries one
OPEN residual (`IsFalsePositiveSecret` is unreachable on the multi-line path),
so the number is kept in place rather than removed.

Item 3 is pinned by a test and intentionally NOT fixed, because fixing it
changes behavior. Item 4 was fixed in Batch 6 (`fab705d`). Item 5 is a performance gap, not a defect — it
is recorded because a spec shipped a false claim that the work was done. Items
6-8 are Batch 5's adjacent gaps: Batch 5 made the entropy floor *consistent*
across paths and deliberately stopped there, so these three remain recorded
rather than fixed.

Batch 8 then closed three of item 7's four paths (jsrecon, json_scanner,
decoder), and Batch 9 closed the last one: `internal/scanner/multiline.go` now
applies the same four filters in the plain-file path's order. Item 7 has no
open remainder on any path and is CLOSED; its one live residual is inside
`IsFalsePositiveSecret`, recorded in the item itself. The paragraph before item
6 ("Batch 5's scope was ... it changed exactly two one-line gates") is
Batch 5's scope and is unchanged; the parenthetical in item 6 that pointed at
`multiline.go:35` as the no-floor exception now describes a fixed path and is
corrected in item 7 below, where the fix is recorded.

Batch 6 removed items 1 and 2 from this list — both `internal/gitscan` security
defects, each reproduced before it was fixed:

- **(was item 1) initial-commit blind spot** — `git diff-tree` ran without
  `--root`, so a secret committed in the root commit and deleted in a later one
  was scanned by nothing. Note the correction: this list previously also
  claimed "a single-commit repo is completely unaudited," which was **wrong** —
  `cmd/scan_run.go:414` runs the working-tree scan and then appends history
  findings, so a single-commit repo was covered for anything present on disk.
  The reproduced defect was narrower. Fixed by `6335a55`.
- **(was item 2) non-repo silence** — `ScanHistory` returned `(nil, nil)` when
  `git log` failed. Fixed by `97a35d6`. The caller still downgrades the error to
  a stderr warning and exits 0; promoting it to a fatal error was deliberately
  left as a separate decision with its own blast radius.

Item 4's `netguard` half is also fixed, by `fab705d`, along with the four legacy
`inet_aton` IPv4 spellings (`2130706433`, `127.1`, `010.0.0.1`, `0x7f.0.0.1`)
that were never recorded here because they had not yet been reproduced. The
follow-on `internalurl`/`netguard` disagreement — closed — and its residual
link-local remainder are recorded as item 9.

See `CHANGELOG.md` `[Unreleased]` for the user-visible effect of item 1:
`--git-history` now reports secrets that were committed and later deleted, so
finding counts go **up**.

One `internal/jsanalysis` issue is pinned by `TestLocalhostRE_UnanchoredSubspanExtraction`:

3. **`localhostRE` under-matches loopback hosts** — the regex at `internal/jsanalysis/analyze.go` knows only three case-sensitive spellings (`localhost`, `127.0.0.1`, `0.0.0.0`) and requires a `:port`, so a JS config value containing `LOCALHOST:8080`, `127.0.0.2:8080` or `[::1]:8080` yields no `InternalURLs` finding — even though `internalurl.IsLoopback` accepts all three and `internal/recon`'s `classifyInternal` already reports them for URLs. The fix is NOT a one-line swap to `IsLoopback`: the same regex is **unanchored**, so it emits a *subspan* of a longer host (`my-localhost:8080` produces the finding `localhost:8080`), which a host-parsing predicate rejects. Widening the vocabulary must therefore fix the anchoring in the same edit, or it trades under-matches for wrong findings; delegating to `IsLoopback` only becomes viable once the extractor emits whole hosts. See the comment at the declaration. Needs its own CHANGELOG'd task — do not fold it into a refactor promising "no behavior change".

4. **CLOSED — `netguard`'s `AllowFetch` admitted zone-scoped IPv6 and legacy
   `inet_aton` IPv4 spellings as if they were plain public hosts.** Fixed by
   `fab705d`: the parser strips the zone and applies the same `IsBlockedIP`
   checks, it does not waive them. No remainder; the classification-package
   side of the same difference is item 9.



One `internal/crawler` gap (Batch 3 spec, work never implemented):

5. **`fetchURL` scratch buffers are allocated per call and never pooled** — Batch 3's design spec listed "`fetchURL` reads through a bounded `io.LimitReader` and returns pooled scratch" as approved-and-completed work. Only the bounded-read half shipped. `fetchURL` (`internal/crawler/crawler.go`) still does a plain `io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))`, so every crawled URL allocates a fresh grow-by-doubling buffer up to the 10MB cap, and the `ConvertToUTF8`/`string(utf8Body)` conversions allocate again on top. `grep -rn "sync.Pool" internal/crawler/` returns nothing — there is no pool in the package at all. The `crawler.BodyPool` var was the orphan hook for this unfinished half; Batch 4d Task 1 deleted it as dead code, which removed the last code-level trace of the gap, so it is recorded here instead. The Batch 3 `CHANGELOG.md` entry makes no pool claim and is accurate as written. **This is a memory optimization, not a refactor** — it needs its own batch, its own CHANGELOG entry, and its own benchmark (allocation/op and RSS on a crawl fixture) before and after; do NOT fold it into a change promising "no behavior change", because a pooled buffer that escapes a `Put` is a use-after-free class bug that `-race` does not reliably catch.

Three gaps adjacent to the Batch 5 entropy-floor work. Batch 5's scope was to make one rule's `entropy_threshold` apply identically on every path that **gates on a floor**; it changed exactly two one-line gates and recorded the rest here. (The qualifier matters: `internal/scanner/multiline.go:35` also called `rule.MatchAll` and ran the ruleset, but applied **no** entropy floor at all, so there was nothing there to align — see item 7. Batch 9 has since given that path a floor, so the parenthetical below describing it as "the exception in kind" is no longer live; the measurement in this item is unchanged.)

6. **The 3.0 floor judges the whole `KEY=value` span, not the value** — `env_generic_secret`'s pattern is `(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})`, which contains **zero capturing groups** (every group is `(?:...)`), and `rules.MatchAll` wraps `FindAllStringIndex`, returning only `[start, end]` of the whole match with no submatch indices. So `secret = text[m[0]:m[1]]` is the entire `MY_SECRET=aaaaaaaa`, never `aaaaaaaa`. Measured with `entropy.Shannon`: the span scores **2.7250**; the value sub-span alone scores **0.0000**. The key name supplies essentially all of the entropy, so a literal 3.0 floor is far weaker than it reads — `MY_SECRET=aaaaaaaa` clears a 2.725 bar only because of the constant `MY_SECRET=` prefix. This affects every rule-matching path that **gates on entropy** equally — `helpers.go:527`/`534`, `scan_stream.go:83`/`90`, `decoder/pipeline.go:158`, `jsrecon/reconstruct.go:403`/`407`, and `json_scanner/scanner.go:98`/`102` each call `MatchAll` and then slice `[m[0]:m[1]]` — so it is not a per-path inconsistency. `internal/scanner/multiline.go:35` **was** the exception in kind rather than in degree: it ran `MatchAll` and sliced `content[m[0]:end]` (`:41`) the same way, but computed no entropy at all, so there was no floor there for the span-vs-value distinction to be wrong about. **That is no longer true** — Batch 9 added the floor to that path, and the measured consequence is that a `docker_compose_secret` span has its entropy judged over the same whole span this item describes (96 repeated characters in the value → 1.756 span entropy, which the 2.0 floor suppresses). So this item's finding now applies to a fourth path, and the multi-line path inherits the same weakness: its span entropy is dominated by the rule's own fixed text, not by the value. **Whether the intent was ever to judge the value alone is a detection-quality question, not a bug fix** — the ruleset was never given a capturing group, so the current behavior is self-consistent and pinned by the Batch 5 tests. Needs its own batch and its own characterization; do NOT "fix" it by adding a capture group, because that silently re-tightens the floor on every path at once.

  **Measured consequence (2026-10-08): the 3.0 floor suppresses nothing realistic.** Because the key name supplies most of the span's entropy, the floor rejects only degenerate input. Over 21 common weak secret values, scored as the full `MY_PASSWORD=<value>` span:

  | value | span Shannon | outcome |
  |---|---|---|
  | `root` | 3.7500 | reported |
  | `letmein` | 4.0370 | reported |
  | `qwerty` | 4.0590 | reported |
  | `hunter2hunter` | 4.0840 | reported |
  | `password` | 4.1220 | reported |
  | `password123` | 4.3500 | reported |

  **21 of 21 reported, 0 suppressed** — the lowest scorer is 3.75, well above the 3.0 bar. The only strings the floor actually rejects are runs of repeated characters (`MY_SECRET=aaaaaaaa` at 2.7250). A rule carrying `entropy_threshold: 3.0` reads as "reject weak secrets"; in practice it rejects repeated characters and nothing else. Batch 5 made three paths agree on this threshold, which is a real consistency win, but the threshold being aligned is close to inert. **Any future work here should start from the measurement, not from the threshold's apparent intent** — and note that raising the floor would not help, since the key name's entropy dominates; only judging the value sub-span (or a length-plus-charset heuristic) would.

7. **CLOSED — `internal/scanner/multiline.go` applied no entropy floor, no FP
   filters and no `RequiresContext`; the last rule-matching path missing them.
   Closed by Batch 9.** Batch 8 closed the other three and Batch 9 this one, so
   all four filters now apply on every rule-matching path, in the plain-file
   path's order (`helpers.go:529`, then `:555-563`): `internal/jsrecon/reconstruct.go`
   — `RequiresContext` at `:416`, the three `IsFalsePositive*` filters at
   `:437-445`; `internal/json_scanner/scanner.go` (ruleset branch only; the
   key-name heuristic at `:70-87` has no `rule` and no matched span, so it has
   nothing to filter) — `:112` and `:134-142`; `internal/decoder/pipeline.go` —
   `:168` and `:182`, which had `Token`/`Email` already at `:206`/`:209`; and
   `internal/scanner/multiline.go` — all four are in the match loop inside
   `ScanMultiLine`. Each path's `RequiresContext` text is a deliberate per-path
   choice, recorded in a comment at the call site: jsrecon checks the
   reconstructed string, json_scanner the key path plus the value, the decoder
   the decoded chunk, and multiline the whole joined window.

   **One carve-out, now in two places:** `IsFalsePositiveToken` is *not* applied
   to `multi_line` rules — on the decoded path (`pipeline.go:206`) and on the
   multi-line path, where the exemption is unconditional because
   `ScanMultiLine`'s loop already skips every non-multi_line rule, so a
   `!rule.MultiLine` guard there would be dead code. Token's hyphen heuristic
   (`>= 3` hyphens, `len > 20`) rejects a full PEM block, and the multi_line
   rules are the CRITICAL `rsa_private_key`/`ec_private_key`/
   `openssh_private_key`/`pgp_private_key` rules, which exist so whole blocks
   are reported. On that path the block matches nothing on the plain
   single-line path either, so suppressing it would make key material in a PEM
   file less visible than the same material nowhere else. `Secret`/`Email`
   still apply, being span-shape-agnostic. Pinned by
   `TestMultiLinePEMBlockStillReported`, which first asserts each fabricated
   block really does trip Token, so the guard cannot pass for the wrong reason.

   **Residual, OPEN — `IsFalsePositiveSecret` is unreachable on the multi-line
   path.** Its `kvPlaceholderRe` (`entropy.go:448`) is anchored `^...$` and its
   capture cannot cross the newline that both structured `multi_line` rules
   (`kubernetes_secret`, `docker_compose_secret`) require in their patterns, so
   the `KEY=value` it looks for is never present in a multi-line span. The
   filter is applied for parity and fires on nothing: a docker-compose secret
   whose value is the literal `changeme` still reports at HIGH. Pinned by
   `TestMultiLineResidualPlaceholderStillReported`. Fixing it means making the
   placeholder extractor newline-tolerant, or judging the value sub-span — both
   are item 6's subject, not a one-line change here.
   `IsFalsePositiveEmail` is likewise inert on this path for a structural
   reason that needs no fix: no `multi_line` rule matches email-shaped text.

   **The floor's measured effect is narrow, and that is the honest shape of the
   win.** Span entropies on the fixture corpus in
   `internal/scanner/multiline_filter_test.go`: private/public-key blocks
   3.952–5.542, `kubernetes_secret` 4.111, a real docker-compose password
   4.894 — all far above the 2.0 floor. The only span the floor removes is a
   run of repeated characters (96 `a`s → 1.756); 72 `a`s → 2.059 still reports,
   and a real file with 64 `a`s still reports at `entropy: 2.187`. So the batch
   removes degenerate repeated-character spans and nothing else. Do NOT read it
   as closing the span-vs-value question in item 6 — it gives that path a floor
   to close it on, which is what the item asked for and all it asked for.

8. **`internal/scanner/url_secrets.go` cannot participate in per-rule thresholds** — `ExtractURLSecrets(line string, path string, lineno int)` takes no `*rules.RuleSet` and iterates a `map[string]string` of URL query-parameter names to synthetic rule names (`access_token` → `url_access_token`, etc.), so there is no `rule` in scope and no `entropy_threshold` to read. Its `url_*` names are heuristics, not rules; `grep '^  - name: url_' internal/rules/builtin.yaml` returns nothing. The `e := entropy.Shannon(val)` at `url_secrets.go:39` (over the parameter **value**, not a `KEY=value` span) keeps its hardcoded `if e < 2.0` at line 40 permanently unless the signature changes. This is recorded so nobody re-attempts the unification Batch 5 declined: `TestURLSecretsRuleNamesAreNotBuiltinRules` (`internal/scanner/url_secrets_entropy_test.go:113`) pins that these names are not builtin rules and fails if anyone tries to add them to the ruleset to make this path generically thresholdable.

9. **`internalurl` and `netguard` disagreed about legacy-IPv4 and zoned-IPv6
   hosts — the disagreement is CLOSED; the link-local asymmetry below remains
   OPEN.** `internal/internalurl` misclassified zone-scoped and legacy-IPv4
   hosts that `netguard` denied, because its three parsed predicates each
   called `net.ParseIP(hostOf(raw))` directly and so inherited every spelling
   `net.ParseIP` rejects. Fixed by Batch 6 Task 5: `netguard` exports the
   resolver it already owned as `ParseHostIP`, `AllowFetch` calls that same
   function, and the three predicates call it too. One parser, one answer per
   host.

   What the gap looked like before the fix:

   | input | `hostOf` | `IsPrivateHost` | `IsLoopback` | `AllowFetch` |
   |---|---|---|---|---|
   | `http://[fe80::1%25eth0]/x` | `fe80::1%eth0` | `false` | `false` | **denied** |
   | `http://127.1/` | `127.1` | `false` | `false` | **denied** |
   | `http://2130706433/` | `2130706433` | `false` | `false` | **denied** |
   | `http://127.0.0.1/` | `127.0.0.1` | `false` | `true` | denied |

   The divergence was the problem: Batch 4c moved `classifyInternal` onto these
   predicates specifically so one address could not be classified one way by
   recon and another by the fetch gate. **Do NOT reintroduce it by calling
   `net.ParseIP` in `internalurl`, or by adding a host→address step to any other
   package** — the exported resolver exists for that, and a second copy is the
   exact regression this item records.

   **Still open — `fe80::1` classifies as a public host in `internalurl` even
   though `netguard` blocks it.** `IsPrivateHost` is RFC 1918 by contract and
   link-local is `IsBlockedIP`'s job, not its own. Task 5 fixed the parser and
   did not widen a category; doing so would be a policy change with its own
   blast radius. Pinned by the `link-local-zoned` group in the parity test so
   the exemption is explicit rather than accidental.

10. **CLOSED — dedup keys were truncated, merging distinct secrets that share
    a long prefix into one finding.** This defect was never given its own §15
    number while it lived; it is recorded here as a CLOSED entry (Batch 7)
    rather than retro-inserted into the open numbering. Two key shapes were
    affected: the Secret-only skip-set keys truncated at 60 chars (8 sites
    across `internal/scanner/helpers.go`, `scan_content.go`, `scan_file.go`,
    `scan_stream.go`), and gitscan's `RuleName+":"+Secret` cross-commit key
    truncated at 80 chars (`internal/gitscan/scanner.go`). Two different
    secrets agreeing on the truncated prefix collapsed to one key and reported
    once. Fixed by `5ff17cc` and `c0977e6`; both keys are now full-length, so
    distinct prefix-sharing secrets report separately (finding counts go UP)
    while identical secrets still dedup. Pinned by
    `internal/scanner/dedup_key_truncation_test.go` and the gitscan history
    collision test. A repo-wide check confirms no `key = key[:60]` /
    `key = key[:80]` truncation remains in production code.

---

## Quick Reference for AI Agents

When working on this codebase:

1. **CI commands**: `go test -race ./...`, `go vet ./...`, `gofmt -l .`
2. **Module path**: `github.com/RA000WL/syck`
3. **Go version**: 1.26+
4. **Rules file**: `internal/rules/builtin.yaml`
5. **Entry point**: `main.go` → `cmd.Execute()`
6. **Core scanning**: `internal/scanner/scan_paths.go` (file walk), `scan_file.go`, `scan_urls.go`, `scan_read.go`
7. **JS analysis**: `internal/jsanalysis/analyze.go`
8. **Subdomain discovery**: `internal/discovery/subdomain.go`
9. **Output**: 7 formats via `internal/formatters/`
10. **Run tests after every change** — `go test -race ./...`
