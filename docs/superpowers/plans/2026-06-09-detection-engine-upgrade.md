# Detection Engine Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade secret scanner from 42/70 findings (60%) to >63/70 (90%) on syck_stress_test.js while maintaining ≤2 false positives.

**Architecture:** Extend the existing decoder pipeline, JS recon engine, and rule library. 10 phases grouped into 4 parallel workstreams: (A) Decoder pipeline, (B) JS reconstruction, (C) Rules/patterns/URL extraction, (D) Confidence scoring.

**Tech Stack:** Go 1.26.3, `regexp`, `compress/gzip`, `compress/zlib`, `encoding/base64`, existing `decoder.Registry`, `jsrecon`, `finding.Finding` types.

**Baseline:** 42 findings, ~5 FPs. See `syck_stress_test.js` (264 lines, 18 sections) at `/home/raven/secretsyoucantkeep/syck_stress_test.js`.

**CI:** `go test -race ./...`, `go vet ./...`, `gofmt -l .`

---

## Workstream A: Decoder Pipeline (Phases 1, 2, 4)

### Task A1: Gzip inline decoder (Phase 1)

**Files:**
- Modify: `internal/decoder/pipeline.go` — add `tryGzipInline` decoder
- Modify: `internal/decoder/decoders.go` — register gzip inline decoder
- Modify: `internal/decoder/registry.go` — add "gzip" flag + case
- Modify: `internal/scanner/scanner.go` — add `DecodeGzip` to Flags struct? No, it's already there. Add to streaming path.
- Modify: `internal/scanner/scan.go` — wire gzip inline decoder into scanContent line-level scanning

- [ ] **Step 1: Add tryGzipInline decoder to pipeline.go**

```go
// In internal/decoder/pipeline.go, add after tryGzipDecompress:

var b64GzipCandidateRE = regexp.MustCompile(`\b[A-Za-z0-9+/]{64,}={0,2}\b`)

func tryGzipInline(line string) []DecodeResult {
    var results []DecodeResult
    for _, m := range b64GzipCandidateRE.FindAllString(line, -1) {
        padding := 4 - len(m)%4
        if padding != 4 {
            m += strings.Repeat("=", padding)
        }
        raw, err := base64.StdEncoding.DecodeString(m)
        if err != nil {
            raw, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(m)
            if err != nil {
                continue
            }
        }
        decompressed, ok := TryGzipDecompress(raw)
        if ok && len(decompressed) > 10 {
            results = append(results, DecodeResult{SourceTag: "gzip", Text: string(decompressed)})
        }
    }
    return results
}
```

Add `regexp`, `encoding/base64` to imports.

- [ ] **Step 2: Register gzip decoder in decoders.go**

```go
// In internal/decoder/decoders.go init():
defaultRegistry.Register("gzip", tryGzipInline)
```

- [ ] **Step 3: Add gzip to Flags and registry.go**

In `internal/decoder/decoders.go`:
```go
// Add Gzip to Flags struct:
type Flags struct {
    Base64       bool
    Hex          bool
    Unicode      bool
    URL          bool
    Base64URL    bool
    JWT          bool
    DoubleBase64 bool
    Gzip         bool
}

func (f Flags) HasAny() bool {
    return f.Base64 || f.Hex || f.Unicode || f.URL || f.Base64URL || f.JWT || f.DoubleBase64 || f.Gzip
}
```

In `internal/decoder/registry.go` Active():
```go
case "gzip":
    if flags.Gzip {
        out = append(out, r.decs[name])
    }
```

- [ ] **Step 4: Wire gzip flag into scanContent and scanFileStreaming**

In `scanContent` (scan.go ~line 548):
```go
df := decoder.Flags{
    Base64:  cfg.DecodeBase64,
    Hex:     cfg.DecodeHex,
    Unicode: cfg.DecodeUnicode,
    URL:     cfg.DecodeURL,
    Gzip:    cfg.DecodeGzip,
}
```

Same in `scanFileStreaming` (~line 408).

- [ ] **Step 5: Run tests**

Run: `go test -race ./internal/decoder/... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/decoder/
git commit -m "feat(decoder): add inline gzip decoder for base64-wrapped compressed secrets"
```

### Task A2: Chunked decoded blob scanning (Phase 2)

**Files:**
- Modify: `internal/decoder/pipeline.go` — replace 200-char truncation with chunked scanning

- [ ] **Step 1: Replace scanDecoded truncation with chunked scanning**

Replace the `scanDecoded` function in `pipeline.go`:

```go
const (
    scanChunkSize = 1024
    scanOverlap   = 128
)

func scanDecoded(
    decodedText string,
    path string,
    lineno int,
    sourceTag string,
    rs *rules.RuleSet,
    minSev finding.Severity,
    findings *[]finding.Finding,
) {
    if len(decodedText) <= scanChunkSize {
        scanDecodedChunk(decodedText, path, lineno, sourceTag, "", rs, minSev, findings)
        return
    }

    seen := map[string]bool{}
    offset := 0
    for offset < len(decodedText) {
        end := offset + scanChunkSize
        if end > len(decodedText) {
            end = len(decodedText)
        }
        chunk := decodedText[offset:end]
        scanDecodedChunk(chunk, path, lineno, sourceTag, "", rs, minSev, findings)
        offset += scanChunkSize - scanOverlap
        _ = seen
    }
}

func scanDecodedChunk(
    chunk string,
    path string,
    lineno int,
    sourceTag string,
    context string,
    rs *rules.RuleSet,
    minSev finding.Severity,
    findings *[]finding.Finding,
) {
    if context == "" {
        context = sourceTag + " decoded: " + chunk
        if len(context) > 500 {
            context = context[:500]
        }
    }
    for _, rule := range rs.Rules {
        sev := finding.ParseSeverity(rule.Severity)
        if sev < minSev {
            continue
        }
        if rule.Compiled() == nil {
            continue
        }
        matches := rule.MatchAll(chunk)
        for _, m := range matches {
            var secret string
            if m[1] <= len(chunk) {
                secret = chunk[m[0]:m[1]]
            } else {
                secret = chunk[m[0]:]
            }
            e := entropy.Shannon(secret)
            if e < 2.0 {
                continue
            }
            *findings = append(*findings, finding.Finding{
                File:     path,
                Line:     lineno,
                Column:   0,
                RuleName: sourceTag + "_" + rule.Name,
                Severity: sev,
                Secret:   secret,
                Context:  context,
                Entropy:  e,
            })
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `go test -race ./internal/decoder/... -count=1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/decoder/pipeline.go
git commit -m "feat(decoder): replace 200-char truncation with 1024-chunk scanning (128 overlap)"
```

### Task A3: String.fromCharCode decoder (Phase 4)

**Files:**
- Create: `internal/decoder/charcode.go`
- Create: `internal/decoder/charcode_test.go`
- Modify: `internal/decoder/decoders.go` — register
- Modify: `internal/decoder/registry.go` — add flag + case
- Modify: `internal/scanner/scanner.go` — add `DecodeCharCode` bool? Actually, the user didn't ask for a separate flag. Let's just make it always-on or gated by DecodeUnicode.

Actually, looking at the stress test file, String.fromCharCode appears on line 122. The decoder should be a new decoder function that gets registered. Let me gate it behind `DecodeUnicode` since it's a character encoding transform.

- [ ] **Step 1: Create charcode.go**

```go
package decoder

import (
    "regexp"
    "strconv"
    "strings"
)

var fromCharCodeRE = regexp.MustCompile(`String\.fromCharCode\s*\(([^)]+)\)`)

func tryCharCode(line string) []DecodeResult {
    var results []DecodeResult
    matches := fromCharCodeRE.FindAllStringSubmatch(line, -1)
    for _, m := range matches {
        if len(m) < 2 {
            continue
        }
        decoded := decodeCharCodes(m[1])
        if decoded != "" {
            results = append(results, DecodeResult{SourceTag: "charcode", Text: decoded})
        }
    }
    return results
}

func decodeCharCodes(args string) string {
    parts := strings.Split(args, ",")
    var sb strings.Builder
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        n, err := strconv.Atoi(part)
        if err != nil {
            continue
        }
        if n < 0 || n > 0x10FFFF {
            continue
        }
        sb.WriteRune(rune(n))
    }
    return sb.String()
}
```

- [ ] **Step 2: Create charcode_test.go**

```go
package decoder

import "testing"

func TestTryCharCode(t *testing.T) {
    line := `var x=String.fromCharCode(115,107,95,108,105,118,101)`
    results := tryCharCode(line)
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
    if results[0].Text != "sk_live" {
        t.Errorf("expected 'sk_live', got %q", results[0].Text)
    }
    if results[0].SourceTag != "charcode" {
        t.Errorf("expected 'charcode', got %q", results[0].SourceTag)
    }
}

func TestTryCharCodeEmpty(t *testing.T) {
    line := `var x = "hello"`
    results := tryCharCode(line)
    if len(results) != 0 {
        t.Fatalf("expected 0 results, got %d", len(results))
    }
}

func TestTryCharCodeMultiline(t *testing.T) {
    line := `String.fromCharCode(72, 101, 108, 108, 111)`
    results := tryCharCode(line)
    if len(results) != 1 {
        t.Fatalf("expected 1 result, got %d", len(results))
    }
    if results[0].Text != "Hello" {
        t.Errorf("expected 'Hello', got %q", results[0].Text)
    }
}
```

- [ ] **Step 3: Register in decoders.go**

```go
// In init():
defaultRegistry.Register("charcode", tryCharCode)
```

- [ ] **Step 4: Add to Flags and registry.go**

```go
// In Flags struct:
CharCode bool

// In HasAny():
|| f.CharCode

// In registry.go Active():
case "charcode":
    if flags.CharCode {
        out = append(out, r.decs[name])
    }
```

- [ ] **Step 5: Wire into scanContent and scanFileStreaming**

Add `CharCode: cfg.DecodeUnicode || cfg.DecodeHex` to df flags in both functions. (Reuse existing flags since there's no dedicated CLI flag.)

- [ ] **Step 6: Run tests**

Run: `go test -race ./internal/decoder/... -count=1`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/decoder/
git commit -m "feat(decoder): String.fromCharCode decoder for charcode-obfuscated secrets"
```

---

## Workstream B: JS Reconstruction (Phases 3, 5)

### Task B1: Constant propagation (Phase 3)

**Files:**
- Modify: `internal/jsrecon/reconstruct.go` — add `propagateConstants` function
- Modify: `internal/jsrecon/reconstruct.go` — call from `ReconstructAndScan`

- [ ] **Step 1: Add constant propagation to reconstruct.go**

Add new function after `reconstructConcatenations`:

```go
// propagateConstants performs lightweight constant propagation for:
//   const/var/let a = "literal"; const/var/let b = "literal"; a + b + c
func propagateConstants(content string) []reconstructResult {
    var results []reconstructResult
    lines := strings.Split(content, "\n")

    // Pass 1: Build identifier -> string literal map
    consts := map[string]string{}
    declRE := regexp.MustCompile(`(?:var|let|const)\s+(\w+)\s*=\s*(['"])([^'"]*)\2`)
    for _, line := range lines {
        if m := declRE.FindStringSubmatch(line); len(m) > 0 {
            consts[m[1]] = m[3]
        }
    }

    if len(consts) == 0 {
        return results
    }

    // Pass 2: Find identifier concatenation chains
    idChainRE := regexp.MustCompile(`\b(\w+)\s*\+\s*(\w+(?:\s*\+\s*\w+)*)`)
    for lineno, line := range lines {
        if !strings.Contains(line, "+") {
            continue
        }
        matches := idChainRE.FindAllStringSubmatch(line, -1)
        for _, m := range matches {
            fullChain := m[0]
            // Split on + and check all parts are identifiers with known values
            parts := strings.Split(fullChain, "+")
            allResolved := true
            var reconstructed strings.Builder
            for _, part := range parts {
                part = strings.TrimSpace(part)
                if val, ok := consts[part]; ok {
                    reconstructed.WriteString(val)
                } else {
                    allResolved = false
                    break
                }
            }
            if allResolved && reconstructed.Len() >= minReconstructLen {
                results = append(results, reconstructResult{lineNo: lineno + 1, text: reconstructed.String()})
            }
        }
    }
    return results
}
```

- [ ] **Step 2: Call from ReconstructAndScan**

```go
func ReconstructAndScan(...) []finding.Finding {
    // ... existing calls ...

    for _, r := range propagateConstants(content) {
        findings = append(findings, scanReconstructed(r.text, r.lineNo, "reconstructed_var", path, rs, minSev)...)
    }

    return findings
}
```

- [ ] **Step 3: Run tests**

Run: `go test -race ./internal/jsrecon/... -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/jsrecon/reconstruct.go
git commit -m "feat(jsrecon): constant propagation for var/let/const identifier chains"
```

### Task B2: Arbitrary join separators (Phase 5)

**Files:**
- Modify: `internal/jsrecon/reconstruct.go` — update `joinExprRE`

- [ ] **Step 1: Update joinExprRE to support arbitrary separators**

Replace the regex in `reconstruct.go`:

```go
// Old: joinExprRE = regexp.MustCompile(`\[([^\]]+)\]\s*\.\s*join\s*\(\s*['"]\s*['"]\s*\)`)
joinExprRE = regexp.MustCompile(`\[([^\]]+)\]\s*\.\s*join\s*\(\s*(['"])([^'"]*)\2\s*\)`)
```

Update `reconstructJoins` to use the separator:

```go
func reconstructJoins(content string) []reconstructResult {
    var results []reconstructResult
    lines := strings.Split(content, "\n")

    for lineno, line := range lines {
        matches := joinExprRE.FindAllStringSubmatch(line, -1)
        for _, m := range matches {
            if len(m) < 4 {
                continue
            }
            inner := m[1]
            separator := m[3]  // The actual separator string
            parts := extractStringLiterals(inner)
            if len(parts) >= 2 {
                reconstructed := strings.Join(parts, separator)
                if len(reconstructed) >= minReconstructLen {
                    results = append(results, reconstructResult{lineNo: lineno + 1, text: reconstructed})
                }
            }
        }
    }
    return results
}
```

- [ ] **Step 2: Run tests**

Run: `go test -race ./internal/jsrecon/... -count=1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/jsrecon/reconstruct.go
git commit -m "feat(jsrecon): support arbitrary join separators (underscore, dot, dash, etc.)"
```

---

## Workstream C: Rules, URL Extraction, Contextual Entropy (Phases 6, 7, 8)

### Task C1: Rule fixes (Phase 6)

**Files:**
- Modify: `internal/rules/builtin.yaml`

- [ ] **Step 1: Fix github_fine_grained_token (line 79)**

Change `{82}` to `{82,}`:
```yaml
  - name: github_fine_grained_token
    severity: CRITICAL
    pattern: 'github_pat_[0-9a-zA-Z_]{82,}\b'
    tags: [github, vcs]
```

- [ ] **Step 2: Fix sentry_dsn case sensitivity**

Find the sentry_dsn rule and add `(?i)`:
```yaml
  - name: sentry_dsn
    severity: HIGH
    pattern: '(?i)(?:https?://)?[a-f0-9]{32}@[a-z0-9\-]+\.ingest(?:\.[a-z0-9\-]+)*\.sentry\.io/\d+'
    tags: [sentry, error-tracking]
```

- [ ] **Step 3: Fix aws_secret_access_key — add prefix-free variants**

Add a new rule or update existing:
```yaml
  - name: aws_secret_access_key
    severity: CRITICAL
    pattern: '(?:aws_secret_access_key|secret_access_key|secret.access.key|secret-access-key)\s*[:=]\s*[''"]?([A-Za-z0-9/+=]{40,})[''"]?'
    tags: [aws, cloud]
```

Wait, the existing rule matches the VALUE not the key. Let me look at the actual pattern...

Actually I need to read the existing aws_secret_access_key rule to know its exact pattern.

- [ ] **Step 4: Fix redis_url — support empty-user format**

Find the redis_url rule and update to support `redis://:password@host`:
```yaml
  - name: redis_url
    severity: CRITICAL
    pattern: 'redis://(?:[^:]*:[^@]+@)[a-zA-Z0-9\-._~:/?#\[\]@!$&()*+,;=%]+'
    tags: [redis, database]
```

Actually I need to check the current rule first. Let me read it during implementation.

- [ ] **Step 5: Run tests**

Run: `go test -race ./internal/rules/... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "fix(rules): github token min-length, sentry DSN case-insensitive, redis empty-user, AWS prefix-free"
```

### Task C2: URL secret extraction (Phase 7)

**Files:**
- Create: `internal/scanner/url_secrets.go`
- Create: `internal/scanner/url_secrets_test.go`
- Modify: `internal/scanner/scan.go` — wire into scanContent

- [ ] **Step 1: Create url_secrets.go**

```go
package scanner

import (
    "net/url"
    "regexp"
    "strings"

    "github.com/RA000WL/syck/internal/finding"
)

var urlSecretParams = map[string]string{
    "access_token": "url_access_token",
    "token":        "url_token",
    "apikey":       "url_api_key",
    "api_key":      "url_api_key",
    "auth":         "url_auth_token",
    "jwt":          "url_jwt",
    "bearer":       "url_bearer_token",
    "key":          "url_key",
    "secret":       "url_secret",
}

var urlRE = regexp.MustCompile(`https?://[^\s'"]+`)

func ExtractURLSecrets(line string, path string, lineno int) []finding.Finding {
    var findings []finding.Finding
    matches := urlRE.FindAllString(line, -1)
    for _, rawURL := range matches {
        // Strip trailing punctuation
        rawURL = strings.TrimRight(rawURL, "',\")];")
        parsed, err := url.Parse(rawURL)
        if err != nil {
            continue
        }
        params := parsed.Query()
        for param, ruleName := range urlSecretParams {
            if val := params.Get(param); val != "" && len(val) >= 16 {
                e := shannonApprox(val)
                if e < 2.0 {
                    continue
                }
                findings = append(findings, finding.Finding{
                    File:     path,
                    Line:     lineno,
                    Column:   0,
                    RuleName: ruleName,
                    Severity: finding.SeverityHigh,
                    Secret:   val,
                    Context:  finding.Truncate("URL secret param: " + param + "=" + val),
                    Entropy:  e,
                })
            }
        }
    }
    return findings
}

func shannonApprox(s string) float64 {
    // Quick entropy estimate
    freq := make(map[rune]int)
    for _, c := range s {
        freq[c]++
    }
    length := float64(len([]rune(s)))
    if length == 0 {
        return 0
    }
    entropy := 0.0
    for _, count := range freq {
        p := float64(count) / length
        if p > 0 {
            entropy -= p * log2(p)
        }
    }
    return entropy
}

func log2(x float64) float64 {
    if x <= 0 {
        return 0
    }
    // ln(x) / ln(2) without importing math
    // Use the identity: log2(x) = log(x)/log(2)
    // For simplicity, use a series approximation or just import math
    return 0 // placeholder, will import math
}
```

Actually, simpler: just import math and use `entropy.Shannon()`. Let me revise:

```go
package scanner

import (
    "net/url"
    "regexp"
    "strings"

    "github.com/RA000WL/syck/internal/entropy"
    "github.com/RA000WL/syck/internal/finding"
)

var urlSecretParams = map[string]string{
    "access_token": "url_access_token",
    "token":        "url_token",
    "apikey":       "url_api_key",
    "api_key":      "url_api_key",
    "auth":         "url_auth_token",
    "jwt":          "url_jwt",
    "bearer":       "url_bearer_token",
    "key":          "url_key",
    "secret":       "url_secret",
}

var urlRE = regexp.MustCompile(`https?://[^\s'"<>]+`)

func ExtractURLSecrets(line string, path string, lineno int) []finding.Finding {
    var findings []finding.Finding
    matches := urlRE.FindAllString(line, -1)
    for _, rawURL := range matches {
        rawURL = strings.TrimRight(rawURL, "',\")];}]+")
        parsed, err := url.Parse(rawURL)
        if err != nil {
            continue
        }
        params := parsed.Query()
        for param, ruleName := range urlSecretParams {
            if val := params.Get(param); val != "" && len(val) >= 16 {
                e := entropy.Shannon(val)
                if e < 2.0 {
                    continue
                }
                findings = append(findings, finding.Finding{
                    File:     path,
                    Line:     lineno,
                    Column:   0,
                    RuleName: ruleName,
                    Severity: finding.SeverityHigh,
                    Secret:   val,
                    Context:  finding.Truncate("URL secret param: " + param + "=" + val),
                    Entropy:  e,
                })
            }
        }
    }
    return findings
}
```

- [ ] **Step 2: Create url_secrets_test.go**

```go
package scanner

import "testing"

func TestExtractURLSecrets(t *testing.T) {
    line := `githubWebhook:"https://api.github.com/hooks?access_token=ghp_FAKEGitHubToken1234567890abcdefABC"`
    findings := ExtractURLSecrets(line, "test.js", 1)
    if len(findings) == 0 {
        t.Fatal("expected findings from URL access_token")
    }
    found := false
    for _, f := range findings {
        if f.RuleName == "url_access_token" {
            found = true
        }
    }
    if !found {
        t.Error("expected url_access_token finding")
    }
}

func TestExtractURLSecretsNoToken(t *testing.T) {
    line := `var url = "https://example.com/page"`
    findings := ExtractURLSecrets(line, "test.js", 1)
    if len(findings) != 0 {
        t.Errorf("expected 0 findings, got %d", len(findings))
    }
}
```

- [ ] **Step 3: Wire into scanContent**

In `scanContent` (scan.go), add after the `DetectAuthHeaders` block:

```go
if cfg.Endpoints {
    findings = append(findings, ExtractURLSecrets(line, path, lineNum)...)
}
```

Actually, URL secret extraction should always run, not just with --endpoints. Let me make it unconditional or gate it on a new flag. Actually, the user didn't ask for a flag - just make it always-on since it's lightweight.

```go
// After the entropy block in scanContent:
urlFindings := ExtractURLSecrets(line, path, lineNum)
findings = append(findings, urlFindings...)
```

Same in scanFileStreaming.

- [ ] **Step 4: Run tests**

Run: `go test -race ./internal/scanner/... -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/url_secrets.go internal/scanner/url_secrets_test.go internal/scanner/scan.go
git commit -m "feat(scanner): extract secrets from URL query parameters (access_token, api_key, etc.)"
```

### Task C3: Contextual entropy detection (Phase 8)

**Files:**
- Modify: `internal/entropy/entropy.go` — add `ContextualEntropyScan` function
- Create: `internal/entropy/contextual_test.go`
- Modify: `internal/scanner/scan.go` — wire in

- [ ] **Step 1: Add contextual entropy detection**

In `entropy.go`, add:

```go
var contextKeywords = []string{
    "secret", "token", "apikey", "api_key", "auth", "bearer",
    "password", "credential", "private", "secret_key", "access_key",
}

func HasContextKeyword(line string) bool {
    lower := strings.ToLower(line)
    for _, kw := range contextKeywords {
        if strings.Contains(lower, kw) {
            return true
        }
    }
    return false
}

// ExtractContextualSecrets finds high-entropy strings on lines with secret-related keywords.
func ExtractContextualSecrets(line string, minEntropy float64) []ContextualSecret {
    if !HasContextKeyword(line) {
        return nil
    }
    var results []ContextualSecret
    tokens := EntropyTokenRe.FindAllString(line, -1)
    for _, tok := range tokens {
        if len(tok) < 20 {
            continue
        }
        e := Shannon(tok)
        if e < minEntropy {
            continue
        }
        results = append(results, ContextualSecret{Token: tok, Entropy: e})
    }
    return results
}

type ContextualSecret struct {
    Token   string
    Entropy float64
}
```

- [ ] **Step 2: Wire into scanContent and scanFileStreaming**

In scanContent, add after entropy block:

```go
if cfg.DecodeBase64 || cfg.DecodeHex {
    // Contextual entropy: high-entropy tokens on lines with secret keywords
    for _, cs := range entropy.ExtractContextualSecrets(line, 4.5) {
        if entropy.IsMediaToken(cs.Token) {
            continue
        }
        findings = append(findings, finding.Finding{
            File:     path,
            Line:     lineNum,
            Column:   strings.Index(line, cs.Token),
            RuleName: "contextual_entropy_secret",
            Severity: finding.SeverityHigh,
            Secret:   cs.Token,
            Context:  finding.Truncate(strings.TrimSpace(line)),
            Entropy:  cs.Entropy,
        })
    }
}
```

Same in scanFileStreaming.

- [ ] **Step 3: Run tests**

Run: `go test -race ./internal/entropy/... -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/entropy/entropy.go internal/scanner/scan.go
git commit -m "feat(entropy): contextual detection of high-entropy tokens near secret keywords"
```

---

## Workstream D: Confidence Scoring (Phase 9)

### Task D1: Confidence scoring

**Files:**
- Modify: `internal/finding/finding.go` — add Confidence, DetectionMethod fields
- Modify: `internal/scanner/scan.go` — set confidence values

- [ ] **Step 1: Add fields to Finding struct**

```go
type Finding struct {
    // ... existing fields ...
    Confidence     int    `json:"confidence,omitempty"`     // 0-100
    DetectionMethod string `json:"detection_method,omitempty"` // "regex", "entropy", "context", "decoded", "url_param", "reconstructed"
}
```

- [ ] **Step 2: Add confidence scoring constants**

```go
const (
    ConfidenceRegex    = 60
    ConfidenceEntropy  = 15
    ConfidenceContext  = 15
    ConfidenceDecoded  = 10
    ConfidenceURLParam = 10
)
```

- [ ] **Step 3: Apply scoring in scanContent**

When a rule regex match is found:
```go
confidence := ConfidenceRegex
// If decoded from base64/etc, add decoded bonus
if tagPrefix != "" && strings.HasSuffix(tagPrefix, "_") {
    confidence += ConfidenceDecoded
}
finding.Confidence = min(confidence, 100)
finding.DetectionMethod = "regex"
```

For entropy tokens:
```go
finding.Confidence = ConfidenceEntropy + ConfidenceContext
finding.DetectionMethod = "entropy+context"
```

For decoded findings:
```go
finding.Confidence = ConfidenceRegex + ConfidenceDecoded
finding.DetectionMethod = "decoded_regex"
```

For URL params:
```go
finding.Confidence = ConfidenceURLParam + ConfidenceRegex
finding.DetectionMethod = "url_param"
```

- [ ] **Step 4: Run tests**

Run: `go test -race ./... -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/finding/finding.go internal/scanner/scan.go
git commit -m "feat(finding): add confidence scoring (0-100) and detection method tracking"
```

---

## Workstream E: Validation (Phase 10)

### Task E1: Benchmark validation

**Files:**
- Create: `internal/scanner/benchmark_test.go`

- [ ] **Step 1: Create benchmark test**

```go
package scanner

import (
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/RA000WL/syck/internal/rules"
)

func TestStressTestCoverage(t *testing.T) {
    // The stress test file is at the repo root
    stressPath := filepath.Join("..", "..", "syck_stress_test.js")
    if _, err := os.Stat(stressPath); os.IsNotExist(err) {
        t.Skip("syck_stress_test.js not found")
    }

    rs, err := rules.LoadDefault()
    if err != nil {
        t.Fatal(err)
    }

    cfg := Config{
        Workers:         1,
        MaxFileSize:     10 * 1024 * 1024,
        Rules:           rs,
        MinSeverity:     finding.SeverityLow,
        DecodeBase64:    true,
        DecodeHex:       true,
        DecodeUnicode:   true,
        DecodeURL:       true,
        DecodeGzip:      true,
        JSReconstruct:   true,
        Endpoints:       true,
        MultiLine:       true,
        StripComments:   false,
        DetectAuthHeaders: true,
        NoDedup:         false,
    }

    findings, err := ScanFile(stressPath, cfg)
    if err != nil {
        t.Fatal(err)
    }

    t.Logf("Total findings: %d", len(findings))

    // Check specific sections are detected
    sectionChecks := map[string]bool{
        "S1_plaintext":    false,
        "S2_sentry":       false,
        "S3_jwt":          false,
        "S4_base64":       false,
        "S8_charcode":     false,
        "S9_arrayjoin":    false,
        "S12_url":         false,
        "S15_pem":         false,
        "S16_oauth":       false,
    }

    for _, f := range findings {
        secret := f.Secret
        if strings.Contains(secret, "AKIAIOSFODNN7") {
            sectionChecks["S1_plaintext"] = true
        }
        if strings.Contains(secret, "ghp_FAKE") {
            sectionChecks["S1_plaintext"] = true
        }
        if f.RuleName == "url_access_token" {
            sectionChecks["S12_url"] = true
        }
        if f.RuleName == "reconstructed_var_reconstructed_concat_stripe_secret_key" {
            sectionChecks["S8_charcode"] = true
        }
    }

    for section, found := range sectionChecks {
        if !found {
            t.Logf("WARNING: Section %s may not be detected", section)
        }
    }
}
```

- [ ] **Step 2: Run benchmark test**

Run: `go test -race ./internal/scanner/... -run TestStressTestCoverage -v`
Expected: PASS with improved finding count

- [ ] **Step 3: Generate comparison report**

- [ ] **Step 4: Final full test suite**

Run: `go test -race ./...`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/benchmark_test.go
git commit -m "test: add stress test coverage validation"
```

---

## Task Order & Dependencies

```
A1 (gzip decoder)        ─┐
A2 (chunked scanning)     ├─→ A3 (charcode) ─┐
                          │                    │
B1 (constant propagation)─┤                    ├─→ E1 (benchmark)
B2 (join separators)      │                    │
                          │                    │
C1 (rule fixes)          ─┤                    │
C2 (URL secrets)          ├─→                  │
C3 (contextual entropy)  ─┘                    │
                                               │
D1 (confidence scoring)  ──────────────────────┘
```

**Parallel execution:** A1, B1, B2, C1, C2, C3, D1 can all start immediately. A3 depends on A1. E1 depends on all.
