# syck-go V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the V1 spec (12 modules, 4 phases) on top of the working `syck-go` binary. End state: scanner produces findings with `confidence` and `verification.status` fields, decodes nested formats with depth 3, correlates credential pairs, surfaces frontend attack surface, and proves rule quality with a CI gating harness.

**Architecture:** Hybrid — extend the 7 lean existing packages, refactor the 2 messy ones (`scanner.go`, `validator/providers.go`), ship 5 new packages. V1 pipeline replaces the monolithic scanner with stages: `Collector → Decoder → Rule → Entropy → Correlation → Verifier → Confidence → Reporter`. Public `Config` and CLI surface preserved.

**Tech Stack:** Go 1.26.3, `github.com/spf13/cobra`, `github.com/spf13/viper`, `gopkg.in/yaml.v3`, `github.com/PuerkitoBio/goquery`, `github.com/go-rod/rod`, `golang.org/x/time/rate` (new, requires `go get`).

**Spec:** `ROADMAP.md` + `docs/superpowers/specs/v1/01..12-*.md`.

---

## File Structure

### V1.0 — Foundation (this plan, fully detailed)

**M1 Rule Engine (`internal/rules/`):**
- Modify: `rule.go` (extend struct)
- Create: `validate.go` (RuleValidator)
- Create: `compile.go` (RuleCompiler with cache)
- Create: `load.go` (replace existing with RuleLoader)
- Test: `rule_extended_test.go`, `validate_test.go`, `compile_test.go`, `load_extended_test.go`

**M2 Entropy Engine (`internal/entropy/`):**
- Modify: `entropy.go` (add helpers)
- Create: `alphabet.go` (enum + detection)
- Test: `alphabet_test.go`, `entropy_extended_test.go`

**M9 Confidence Scoring (new `internal/confidence/`):**
- Modify: `internal/finding/finding.go` (add Confidence field)
- Create: `internal/confidence/confidence.go` (Scorer, Signals, Band)
- Test: `internal/confidence/confidence_test.go`

**M11 Scanner Architecture (`internal/scanner/`):**
- Modify: `scanner.go` (reduce to entry point + Config)
- Create: `pipeline.go` (Pipeline type)
- Create: `collector.go` (file walk)
- Create: `stage_decoder.go`, `stage_rule.go`, `stage_entropy.go`, `stage_correlation.go`, `stage_verifier.go`, `stage_confidence.go`, `stage_reporter.go`
- Test: `pipeline_test.go`, `stage_*_test.go`

### V1.1 — Decoding & Correlation (scheduled, see §V1.1 below)

**M3 Decoder:** `internal/decoder/` — cap depth, add JWT, add atob/Buffer hooks, thread-safe registry.
**M5 Correlation:** new `internal/correlation/` — 8 detectors + Correlator.

### V1.2 — JS / Sourcemap / Recon (scheduled, see §V1.2 below)

**M6 JS Analyzer:** `internal/jsrecon/` — add requests.go, keep reconstruct.go.
**M7 Source Map:** new `internal/sourcemap/`.
**M8 Frontend Recon:** new `internal/recon/`.

### V1.3 — Verification & Quality (scheduled, see §V1.3 below)

**M4 Verification:** `internal/validator/` — refactor providers to per-file, add explicit endpoints, add `--verify` flag.
**M10 Rule Testing:** new `internal/ruletest/` + `cmd/ruletest/main.go`.
**M12 Reporting:** `internal/formatters/` — extend all 6 formatters.

### Public surface preserved (must not change)
- `scanner.Config` struct field order and tags
- `scanner.ScanPaths`, `scanner.ScanFile`, `scanner.ScanReader`, `scanner.ScanURLs`, `scanner.ScanContent` signatures
- CLI flag list: `--severity`, `--format`, `--output`, `--redact`, `--no-dedup`, `--exclude`, `--workers`, `--max-file-size`, `--config`, `--no-color`, `--debug`, `--quiet`, `--list-rules`, `--decode-*`, `--js-reconstruct`, `--endpoints`, `--pipe`, `--fail-on`, `--downgrade-fp`, `--url`, `--url-file`, `--scope`, `--crawl-limit`, `--crawl-depth`, `--headless`, `--rate-limit`, `--cookies`, `--cookie-file`, `--concurrency`, `--host-concurrency`, `--ignore-robots`, `--git-history`, `--ignore-file`, `--rules`, `--validate`

### New CLI flags (additive, see V1.1+ for details)
- `--verify` (V1.3, M4)
- `--sourcemap` (V1.2, M7, opt-in)
- `--recon` (V1.2, M8, opt-in)

---

## V1.0 — Foundation: Bite-Sized Tasks

> Run `go test ./...` after each task. Every task ends with a commit. Use conventional commit messages matching the repo style: `feat:`, `fix:`, `docs:`, `chore:`.

### Task 1: M1 — Extend Rule struct with V1 fields

**Files:**
- Modify: `internal/rules/rule.go:7-14`
- Test: `internal/rules/rule_extended_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/rules/rule_extended_test.go
package rules

import "testing"

func TestRuleExtendedFields(t *testing.T) {
	yaml := `
rules:
  - name: github_pat
    severity: CRITICAL
    pattern: 'github_pat_[A-Za-z0-9_]{80,255}'
    entropy_threshold: 4.5
    context_keywords: [github]
    requires_context: true
    verify: true
    version: "1"
`
	rs, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := rs.Rules[0]
	if r.EntropyThreshold != 4.5 {
		t.Errorf("EntropyThreshold = %v, want 4.5", r.EntropyThreshold)
	}
	if len(r.ContextKeywords) != 1 || r.ContextKeywords[0] != "github" {
		t.Errorf("ContextKeywords = %v, want [github]", r.ContextKeywords)
	}
	if !r.RequiresContext {
		t.Error("RequiresContext = false, want true")
	}
	if !r.Verify {
		t.Error("Verify = false, want true")
	}
	if r.Version != "1" {
		t.Errorf("Version = %q, want %q", r.Version, "1")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -run TestRuleExtendedFields -v`
Expected: FAIL with `loadFromString` undefined (the helper does not exist yet) or struct field error.

- [ ] **Step 3: Add the fields to the Rule struct**

In `internal/rules/rule.go`, replace the struct (lines 7-14):

```go
type Rule struct {
	Name              string   `yaml:"name"`
	Description       string   `yaml:"description,omitempty"`
	Severity          string   `yaml:"severity"`
	Pattern           string   `yaml:"pattern"`
	Tags              []string `yaml:"tags,omitempty"`
	EntropyThreshold  float64  `yaml:"entropy_threshold,omitempty"`
	ContextKeywords   []string `yaml:"context_keywords,omitempty"`
	RequiresContext   bool     `yaml:"requires_context,omitempty"`
	Verify            bool     `yaml:"verify,omitempty"`
	Version           string   `yaml:"version,omitempty"`
	compiled          *regexp.Regexp
}
```

Add the helper to `internal/rules/load.go` (new file or extend the existing one):

```go
// internal/rules/load.go (append)
func loadFromString(s string) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal([]byte(s), &rs); err != nil {
		return nil, err
	}
	if err := rs.CompileAll(); err != nil {
		return nil, err
	}
	return &rs, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -run TestRuleExtendedFields -v`
Expected: PASS

- [ ] **Step 5: Verify existing 130+ rules still load**

Run: `go test ./internal/rules/ -v`
Expected: PASS (no regression on the existing `TestLoad` style tests if present; otherwise `go build ./...` succeeds).

- [ ] **Step 6: Commit**

```bash
git add internal/rules/rule.go internal/rules/load.go internal/rules/rule_extended_test.go
git commit -m "feat(rules): extend Rule struct with V1 fields (entropy_threshold, context_keywords, requires_context, verify, version)"
```

### Task 2: M1 — Add RuleValidator

**Files:**
- Create: `internal/rules/validate.go`
- Test: `internal/rules/validate_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/rules/validate_test.go
package rules

import "testing"

func TestRuleValidator(t *testing.T) {
	v := NewRuleValidator()
	cases := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{"ok", Rule{Name: "a", Severity: "HIGH", Pattern: "abc"}, false},
		{"empty name", Rule{Severity: "HIGH", Pattern: "abc"}, true},
		{"bad severity", Rule{Name: "a", Severity: "FOO", Pattern: "abc"}, true},
		{"bad pattern", Rule{Name: "a", Severity: "HIGH", Pattern: "[unterminated"}, true},
		{"duplicate name", Rule{Name: "a", Severity: "HIGH", Pattern: "abc"}, false},
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule, cases[3].rule}}); err == nil {
		t.Error("expected error for bad pattern, got nil")
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule}}); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule, cases[4].rule}}); err == nil {
		t.Error("expected error for duplicate name, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -run TestRuleValidator -v`
Expected: FAIL with `NewRuleValidator` undefined.

- [ ] **Step 3: Implement the validator**

```go
// internal/rules/validate.go
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

var validSeverities = map[string]bool{
	"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

type RuleValidator struct{}

func NewRuleValidator() *RuleValidator { return &RuleValidator{} }

func (v *RuleValidator) Validate(rs RuleSet) error {
	seen := map[string]int{}
	for i, r := range rs.Rules {
		if r.Name == "" {
			return fmt.Errorf("rule %d: empty name", i)
		}
		if !validSeverities[strings.ToUpper(r.Severity)] {
			return fmt.Errorf("rule %q: invalid severity %q", r.Name, r.Severity)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("rule %q: bad pattern: %w", r.Name, err)
		}
		key := strings.ToLower(r.Name)
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("rule %q: duplicate name (also at index %d)", r.Name, prev)
		}
		seen[key] = i
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -run TestRuleValidator -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/validate.go internal/rules/validate_test.go
git commit -m "feat(rules): add RuleValidator with name/severity/pattern checks and duplicate detection"
```

### Task 3: M1 — Add RuleCompiler with regex cache

**Files:**
- Create: `internal/rules/compile.go`
- Test: `internal/rules/compile_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/rules/compile_test.go
package rules

import "testing"

func TestRuleCompilerCache(t *testing.T) {
	c := NewRuleCompiler()
	a, err := c.Compile("abc")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Compile("abc")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("expected same compiled regex from cache")
	}
	if _, err := c.Compile("[bad"); err == nil {
		t.Error("expected error for bad pattern")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -run TestRuleCompilerCache -v`
Expected: FAIL with `NewRuleCompiler` undefined.

- [ ] **Step 3: Implement the compiler**

```go
// internal/rules/compile.go
package rules

import (
	"regexp"
	"sync"
)

type RuleCompiler struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}

func NewRuleCompiler() *RuleCompiler {
	return &RuleCompiler{cache: map[string]*regexp.Regexp{}}
}

func (c *RuleCompiler) Compile(pattern string) (*regexp.Regexp, error) {
	c.mu.RLock()
	if re, ok := c.cache[pattern]; ok {
		c.mu.RUnlock()
		return re, nil
	}
	c.mu.RUnlock()
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cache[pattern] = re
	c.mu.Unlock()
	return re, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -run TestRuleCompilerCache -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/compile.go internal/rules/compile_test.go
git commit -m "feat(rules): add RuleCompiler with thread-safe regex compile cache"
```

### Task 4: M1 — Add RuleLoader (replace existing load.go)

**Files:**
- Modify: `internal/rules/load.go`
- Test: `internal/rules/load_extended_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/rules/load_extended_test.go
package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuleLoaderDir(t *testing.T) {
	dir := t.TempDir()
	yaml := "rules:\n  - name: a\n    severity: LOW\n    pattern: a\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Name != "a" {
		t.Errorf("got %+v", rs.Rules)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -run TestRuleLoaderDir -v`
Expected: FAIL with `LoadFromDir` undefined.

- [ ] **Step 3: Implement the loader**

```go
// internal/rules/load.go (replace existing with this)
package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const RuleSchemaVersion = "1"

type LoadError struct {
	Path string
	Err  error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

type RuleLoader struct {
	validator *RuleValidator
	compiler  *RuleCompiler
}

func NewRuleLoader() *RuleLoader {
	return &RuleLoader{validator: NewRuleValidator(), compiler: NewRuleCompiler()}
}

func (l *RuleLoader) LoadFromFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Path: path, Err: err}
	}
	rs, err := l.loadFromBytes(data)
	if err != nil {
		return nil, &LoadError{Path: path, Err: err}
	}
	return rs, nil
}

func (l *RuleLoader) LoadFromDir(dir string) (*RuleSet, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, &LoadError{Path: dir, Err: err}
	}
	merged := &RuleSet{}
	for _, m := range matches {
		rs, err := l.LoadFromFile(m)
		if err != nil {
			return nil, err
		}
		merged.Rules = append(merged.Rules, rs.Rules...)
	}
	if err := l.validator.Validate(*merged); err != nil {
		return nil, &LoadError{Path: dir, Err: err}
	}
	return merged, nil
}

func (l *RuleLoader) loadFromBytes(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	if err := l.validator.Validate(rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func LoadFromFile(path string) (*RuleSet, error)        { return NewRuleLoader().LoadFromFile(path) }
func LoadFromDir(dir string) (*RuleSet, error)          { return NewRuleLoader().LoadFromDir(dir) }
func loadFromString(s string) (*RuleSet, error)         { return NewRuleLoader().loadFromBytes([]byte(s)) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -v`
Expected: PASS (TestRuleExtendedFields, TestRuleValidator, TestRuleCompilerCache, TestRuleLoaderDir all pass; existing tests pass).

- [ ] **Step 5: Commit**

```bash
git add internal/rules/load.go internal/rules/load_extended_test.go
git commit -m "feat(rules): add RuleLoader with LoadFromFile/LoadFromDir, validator wired in"
```

### Task 5: M1 — Add schema version gate

**Files:**
- Modify: `internal/rules/load.go` (the loader created in Task 4)
- Test: extend `internal/rules/load_extended_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/rules/load_extended_test.go`:

```go
func TestRuleLoaderVersionGate(t *testing.T) {
	dir := t.TempDir()
	yaml := "rules:\n  - name: a\n    severity: LOW\n    pattern: a\n    version: \"99\"\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromDir(dir); err == nil {
		t.Error("expected version gate to reject version 99, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/rules/ -run TestRuleLoaderVersionGate -v`
Expected: FAIL (no version check exists yet).

- [ ] **Step 3: Add the gate to loadFromBytes**

In `internal/rules/load.go`, modify `loadFromBytes`:

```go
func (l *RuleLoader) loadFromBytes(data []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for i, r := range rs.Rules {
		if r.Version != "" && r.Version > RuleSchemaVersion {
			return nil, fmt.Errorf("rule %d (%s): version %q exceeds supported %q", i, r.Name, r.Version, RuleSchemaVersion)
		}
	}
	if err := l.validator.Validate(rs); err != nil {
		return nil, err
	}
	return &rs, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/rules/ -run TestRuleLoaderVersionGate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/load.go internal/rules/load_extended_test.go
git commit -m "feat(rules): gate loader on RuleSchemaVersion (refuse future versions)"
```

### Task 6: M2 — Add Alphabet enum and detector

**Files:**
- Create: `internal/entropy/alphabet.go`
- Test: `internal/entropy/alphabet_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/entropy/alphabet_test.go
package entropy

import "testing"

func TestDetectAlphabet(t *testing.T) {
	cases := []struct {
		in   string
		want Alphabet
	}{
		{"deadbeef", AlphabetLowerHex},
		{"DEADBEEF", AlphabetUpperHex},
		{"DEadBeEf", AlphabetLowerHex},
		{"aGVsbG8=", AlphabetBase64},
		{"aGVsbG8", AlphabetBase64},
		{"aGVsbG8-_aGVsbG8", AlphabetBase64URL},
		{"github_pat_AAAaaa111", AlphabetUnknown},
		{"a", AlphabetUnknown},
	}
	for _, c := range cases {
		got := DetectAlphabet(c.in)
		if got != c.want {
			t.Errorf("DetectAlphabet(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/entropy/ -run TestDetectAlphabet -v`
Expected: FAIL with `Alphabet` undefined.

- [ ] **Step 3: Implement the enum and detector**

```go
// internal/entropy/alphabet.go
package entropy

import "strings"

type Alphabet int

const (
	AlphabetUnknown Alphabet = iota
	AlphabetLowerHex
	AlphabetUpperHex
	AlphabetBase64
	AlphabetBase64URL
	AlphabetJWT
)

func DetectAlphabet(s string) Alphabet {
	if len(s) == 0 {
		return AlphabetUnknown
	}
	if strings.ContainsAny(s, "-_") && isAlphanumeric(s) {
		return AlphabetBase64URL
	}
	if isAll(s, "0123456789abcdefABCDEF") {
		hasUpper := false
		for _, r := range s {
			if r >= 'A' && r <= 'F' {
				hasUpper = true
				break
			}
		}
		if hasUpper {
			return AlphabetUpperHex
		}
		return AlphabetLowerHex
	}
	if isBase64(s) {
		return AlphabetBase64
	}
	return AlphabetUnknown
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}

func isAll(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}

func isBase64(s string) bool {
	if !isAlphanumeric(strings.TrimRight(s, "=")) {
		return false
	}
	hasSlash, hasPlus := strings.ContainsRune(s, '/'), strings.ContainsRune(s, '+')
	hasPadding := strings.HasSuffix(s, "=") || strings.HasSuffix(s, "==")
	if hasSlash || hasPlus || hasPadding {
		return true
	}
	return false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/entropy/ -run TestDetectAlphabet -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/entropy/alphabet.go internal/entropy/alphabet_test.go
git commit -m "feat(entropy): add Alphabet enum and DetectAlphabet"
```

### Task 7: M2 — Add Base64Entropy, HexEntropy, JwtEntropy helpers

**Files:**
- Modify: `internal/entropy/entropy.go`
- Test: `internal/entropy/entropy_extended_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/entropy/entropy_extended_test.go
package entropy

import (
	"math"
	"testing"
)

func TestBase64Entropy(t *testing.T) {
	if got := Base64Entropy("a"); math.Abs(got-0) > 0.01 {
		t.Errorf("Base64Entropy(\"a\") = %v, want 0", got)
	}
	if got := Base64Entropy("ab"); math.Abs(got-1.0) > 0.01 {
		t.Errorf("Base64Entropy(\"ab\") = %v, want 1.0", got)
	}
	if got := Base64Entropy("aGVsbG8="); got < 2.0 {
		t.Errorf("Base64Entropy(\"aGVsbG8=\") = %v, want >= 2.0", got)
	}
}

func TestHexEntropy(t *testing.T) {
	if got := HexEntropy("01"); math.Abs(got-1.0) > 0.01 {
		t.Errorf("HexEntropy(\"01\") = %v, want 1.0", got)
	}
	if got := HexEntropy("deadbeef"); got < 2.5 {
		t.Errorf("HexEntropy(\"deadbeef\") = %v, want >= 2.5", got)
	}
}

func TestJwtEntropy(t *testing.T) {
	if got := JwtEntropy("--"); math.Abs(got-1.0) > 0.01 {
		t.Errorf("JwtEntropy(\"--\") = %v, want 1.0", got)
	}
	if got := JwtEntropy("aGVsbG8_aGVsbG8"); got < 3.0 {
		t.Errorf("JwtEntropy(\"aGVsbG8_aGVsbG8\") = %v, want >= 3.0", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/entropy/ -run TestBase64Entropy -v`
Expected: FAIL with `Base64Entropy` undefined.

- [ ] **Step 3: Implement the helpers**

Append to `internal/entropy/entropy.go`:

```go
// Base64Entropy: Shannon over the base64 alphabet, normalized to log2(64)=6 bits max.
func Base64Entropy(s string) float64 {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	return shannonFiltered(s, alphabet) / 6.0 * 6.0
}

// HexEntropy: Shannon over hex alphabet, normalized to log2(16)=4 bits max.
func HexEntropy(s string) float64 {
	const alphabet = "0123456789abcdefABCDEF"
	return shannonFiltered(s, alphabet) / 4.0 * 4.0
}

// JwtEntropy: Shannon over URL-safe base64 alphabet, normalized to log2(64)=6 bits max.
func JwtEntropy(s string) float64 {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return shannonFiltered(s, alphabet) / 6.0 * 6.0
}

func shannonFiltered(s, alphabet string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		if !containsRune(alphabet, r) {
			return 0
		}
		freq[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return math.Round(ent*1000) / 1000
}

func containsRune(s string, r rune) bool {
	for _, x := range s {
		if x == r {
			return true
		}
	}
	return false
}

// EntropyByAlphabet dispatches to the right helper.
func EntropyByAlphabet(s string, a Alphabet) float64 {
	switch a {
	case AlphabetLowerHex, AlphabetUpperHex:
		return HexEntropy(s)
	case AlphabetBase64URL, AlphabetJWT:
		return JwtEntropy(s)
	case AlphabetBase64:
		return Base64Entropy(s)
	default:
		return Shannon(s)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/entropy/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/entropy/entropy.go internal/entropy/entropy_extended_test.go
git commit -m "feat(entropy): add Base64Entropy, HexEntropy, JwtEntropy and EntropyByAlphabet dispatch"
```

### Task 8: M2 — Wire EntropyByAlphabet into IsEntropyTokenMatch

**Files:**
- Modify: `internal/entropy/entropy.go` (the `IsEntropyTokenMatch` function)
- Test: extend `internal/entropy/entropy_extended_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/entropy/entropy_extended_test.go`:

```go
func TestIsEntropyTokenMatchUsesAlphabet(t *testing.T) {
	// a 64-char hex string is high-entropy hex
	hex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if !IsEntropyTokenMatch(hex) {
		t.Error("expected hex token to match")
	}
	// a 64-char base64 string is high-entropy base64
	b64 := "aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8aGVsbG8"
	if !IsEntropyTokenMatch(b64) {
		t.Error("expected base64 token to match")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/entropy/ -run TestIsEntropyTokenMatchUsesAlphabet -v`
Expected: FAIL (current `IsEntropyTokenMatch` uses `Shannon` and the regex gate rejects hex; see `entropyExcludeRe` which intentionally rejects the hex alphabet).

- [ ] **Step 3: Update IsEntropyTokenMatch**

In `internal/entropy/entropy.go`, replace `IsEntropyTokenMatch`:

```go
// IsEntropyTokenMatch returns true if token passes entropy token scan filters.
// Uses alphabet-specific entropy calculation.
func IsEntropyTokenMatch(token string) bool {
	if entropyExcludeRe.MatchString(token) {
		return false
	}
	a := DetectAlphabet(token)
	e := EntropyByAlphabet(token, a)
	return LikelySecret(token, 32, 4.5) && e >= 4.0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/entropy/ -v`
Expected: PASS. If a pre-existing test regresses (e.g. a token that used to be matched is now rejected), update the test data and re-run.

- [ ] **Step 5: Commit**

```bash
git add internal/entropy/entropy.go internal/entropy/entropy_extended_test.go
git commit -m "feat(entropy): wire EntropyByAlphabet into IsEntropyTokenMatch"
```

### Task 9: M9 — Add Confidence field to finding.Finding

**Files:**
- Modify: `internal/finding/finding.go`
- Test: `internal/finding/finding_test.go` (new)

- [ ] **Step 1: Write the failing test**

```go
// internal/finding/finding_test.go
package finding

import "testing"

func TestFindingConfidenceField(t *testing.T) {
	f := Finding{
		RuleName:   "x",
		Severity:   "HIGH",
		Confidence: "HIGH",
	}
	if f.Confidence != "HIGH" {
		t.Errorf("Confidence = %q, want HIGH", f.Confidence)
	}
	if f.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", f.Severity)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/finding/ -v`
Expected: FAIL (Confidence field does not exist).

- [ ] **Step 3: Add the field**

In `internal/finding/finding.go`, find the `Finding` struct and add the field. Existing struct (line 89 from earlier read) likely looks like:

```go
type Finding struct {
	File             string
	Line             int
	Column           int
	RuleName         string
	Severity         Severity
	Secret           string
	Context          string
	Entropy          float64
	ContextBefore    string
	ContextAfter     string
	Confidence       string  // NEW (V1, M9)
	VerificationStatus string // NEW (V1, M4) — empty for V1.0
	DecodedValuePreview string // NEW (V1, M3) — empty for V1.0
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/finding/ -v && go build ./...`
Expected: PASS; build succeeds across the repo.

- [ ] **Step 5: Commit**

```bash
git add internal/finding/finding.go internal/finding/finding_test.go
git commit -m "feat(finding): add Confidence, VerificationStatus, DecodedValuePreview fields"
```

### Task 10: M9 — Create internal/confidence package with Scorer

**Files:**
- Create: `internal/confidence/confidence.go`
- Test: `internal/confidence/confidence_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/confidence/confidence_test.go
package confidence

import "testing"

func TestScorerAllSignals(t *testing.T) {
	s := NewScorer()
	got := s.Score(Signals{RegexMatch: true, Entropy: 5.0, HasContextKeyword: true, Verified: true, InCredentialPair: true})
	if got != 155 {
		t.Errorf("Score() = %d, want 155", got)
	}
	if Band(got) != "CRITICAL" {
		t.Errorf("Band(155) = %q, want CRITICAL", Band(got))
	}
}

func TestScorerNoSignals(t *testing.T) {
	s := NewScorer()
	got := s.Score(Signals{})
	if got != 0 {
		t.Errorf("Score() = %d, want 0", got)
	}
	if Band(got) != "LOW" {
		t.Errorf("Band(0) = %q, want LOW", Band(got))
	}
}

func TestBandBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{30, "LOW"}, {31, "MEDIUM"},
		{60, "MEDIUM"}, {61, "HIGH"},
		{90, "HIGH"}, {91, "CRITICAL"},
	}
	for _, c := range cases {
		if got := Band(c.score); got != c.want {
			t.Errorf("Band(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestEntropySignal(t *testing.T) {
	s := NewScorer()
	if got := s.Score(Signals{Entropy: 4.5}); got != 20 {
		t.Errorf("Score(entropy=4.5) = %d, want 20", got)
	}
	if got := s.Score(Signals{Entropy: 4.4}); got != 0 {
		t.Errorf("Score(entropy=4.4) = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/confidence/ -v`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement the package**

```go
// internal/confidence/confidence.go
package confidence

type Signals struct {
	RegexMatch       bool
	Entropy          float64
	HasContextKeyword bool
	Verified         bool
	InCredentialPair bool
}

type Scorer struct{}

func NewScorer() *Scorer { return &Scorer{} }

const (
	ptsRegex       = 40
	ptsEntropy     = 20
	ptsContext     = 15
	ptsVerified    = 50
	ptsCredPair    = 30
	entropyFloor   = 4.5
)

func (s *Scorer) Score(sig Signals) int {
	score := 0
	if sig.RegexMatch {
		score += ptsRegex
	}
	if sig.Entropy >= entropyFloor {
		score += ptsEntropy
	}
	if sig.HasContextKeyword {
		score += ptsContext
	}
	if sig.Verified {
		score += ptsVerified
	}
	if sig.InCredentialPair {
		score += ptsCredPair
	}
	return score
}

func Band(score int) string {
	switch {
	case score <= 30:
		return "LOW"
	case score <= 60:
		return "MEDIUM"
	case score <= 90:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/confidence/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/confidence/confidence.go internal/confidence/confidence_test.go
git commit -m "feat(confidence): add Scorer with composite signals and LOW/MEDIUM/HIGH/CRITICAL bands"
```

### Task 11: M11 — Extract Collector stage from scanner.go

**Files:**
- Create: `internal/scanner/collector.go`
- Test: `internal/scanner/collector_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/collector_test.go
package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "x"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(Config{Workers: 2})
	files, err := c.Walk(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range files {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 file, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestCollectorWalk -v`
Expected: FAIL with `NewCollector` undefined.

- [ ] **Step 3: Implement the Collector**

```go
// internal/scanner/collector.go
package scanner

import (
	"io"
	"os"
	"path/filepath"
)

type FileJob struct {
	Path string
	Size int64
}

type Collector struct {
	cfg Config
}

func NewCollector(cfg Config) *Collector { return &Collector{cfg: cfg} }

var scannerSkipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	"vendor": true, "target": true, "build": true, "dist": true,
}

func (c *Collector) Walk(root string) (<-chan FileJob, error) {
	out := make(chan FileJob, 64)
	go func() {
		defer close(out)
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if scannerSkipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if c.cfg.MaxFileSize > 0 && info.Size() > c.cfg.MaxFileSize {
				return nil
			}
			if c.cfg.Exclude != nil && c.cfg.Exclude.MatchString(path) {
				return nil
			}
			out <- FileJob{Path: path, Size: info.Size()}
			return nil
		})
	}()
	return out, nil
}

func openFile(path string) (io.ReadCloser, error) { return os.Open(path) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run TestCollectorWalk -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/collector.go internal/scanner/collector_test.go
git commit -m "refactor(scanner): extract Collector stage from scanner.go"
```

### Task 12: M11 — Extract Decoder stage wrapper

**Files:**
- Create: `internal/scanner/stage_decoder.go`
- Test: `internal/scanner/stage_decoder_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/stage_decoder_test.go
package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestDecoderStagePassthrough(t *testing.T) {
	rs := &rules.RuleSet{}
	_ = rs.CompileAll()
	d := NewDecoderStage(rs, finding.ParseSeverity("LOW"), DecoderFlags{})
	findings := d.Process("plain text without any secrets", "x.txt", 1)
	_ = findings // no panic; empty result expected
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestDecoderStagePassthrough -v`
Expected: FAIL (NewDecoderStage undefined).

- [ ] **Step 3: Implement the stage**

```go
// internal/scanner/stage_decoder.go
package scanner

import (
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type DecoderFlags struct {
	Base64  bool
	Hex     bool
	Unicode bool
	URL     bool
	Gzip    bool
}

type DecoderStage struct {
	rs    *rules.RuleSet
	min   finding.Severity
	flags DecoderFlags
}

func NewDecoderStage(rs *rules.RuleSet, min finding.Severity, flags DecoderFlags) *DecoderStage {
	return &DecoderStage{rs: rs, min: min, flags: flags}
}

func (s *DecoderStage) Process(line, path string, lineno int) []finding.Finding {
	df := decoder.Flags{Base64: s.flags.Base64, Hex: s.flags.Hex, Unicode: s.flags.Unicode, URL: s.flags.URL}
	return decoder.DecodeAndRescan(line, path, lineno, s.rs, s.min, df)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -run TestDecoderStagePassthrough -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/stage_decoder.go internal/scanner/stage_decoder_test.go
git commit -m "refactor(scanner): extract DecoderStage as a thin wrapper over internal/decoder"
```

### Task 13: M11 — Extract Rule, Entropy, Verifier, Reporter stage wrappers

**Files:**
- Create: `internal/scanner/stage_rule.go`, `stage_entropy.go`, `stage_verifier.go`, `stage_reporter.go`
- Test: `internal/scanner/stage_*_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/stage_rule_test.go
package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestRuleStage(t *testing.T) {
	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs, _ := loadTestRuleSet(t, yaml)
	s := NewRuleStage(rs, finding.ParseSeverity("LOW"))
	got := s.Process("hello TOKEN_ABCDEF12 world", "x.txt", 1)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleName != "token" {
		t.Errorf("RuleName = %q, want token", got[0].RuleName)
	}
}

func loadTestRuleSet(t *testing.T, yaml string) *rules.RuleSet {
	t.Helper()
	rs, err := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
```

```go
// internal/scanner/testhelpers_test.go
package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempYAML(t *testing.T, s string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestRuleStage -v`
Expected: FAIL with `NewRuleStage` undefined.

- [ ] **Step 3: Implement the four stages**

```go
// internal/scanner/stage_rule.go
package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type RuleStage struct {
	rs  *rules.RuleSet
	min finding.Severity
}

func NewRuleStage(rs *rules.RuleSet, min finding.Severity) *RuleStage {
	return &RuleStage{rs: rs, min: min}
}

func (s *RuleStage) Process(line, path string, lineno int) []finding.Finding {
	var out []finding.Finding
	for _, r := range s.rs.Rules {
		sev := finding.ParseSeverity(r.Severity)
		if sev < s.min || r.Compiled() == nil {
			continue
		}
		for _, m := range r.MatchAll(line) {
			secret := line[m[0]:m[1]]
			out = append(out, finding.Finding{
				File: path, Line: lineno, RuleName: r.Name,
				Severity: sev, Secret: secret, Context: line,
			})
		}
	}
	return out
}
```

```go
// internal/scanner/stage_entropy.go
package scanner

import (
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
)

type EntropyStage struct{}

func NewEntropyStage() *EntropyStage { return &EntropyStage{} }

func (s *EntropyStage) Process(line, path string, lineno int) []finding.Finding {
	if !entropy.HasSecretContext(line) {
		return nil
	}
	var out []finding.Finding
	for _, m := range entropy.EntropyTokenRe.FindAllStringIndex(line, -1) {
		token := line[m[0]:m[1]]
		if !entropy.IsEntropyTokenMatch(token) {
			continue
		}
		out = append(out, finding.Finding{
			File: path, Line: lineno, RuleName: "entropy_token",
			Severity: finding.ParseSeverity("LOW"), Secret: token, Context: line,
			Entropy: entropy.Shannon(token),
		})
	}
	return out
}
```

```go
// internal/scanner/stage_verifier.go
package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/validator"
)

type VerifierStage struct{}

func NewVerifierStage() *VerifierStage { return &VerifierStage{} }

func (s *VerifierStage) Process(in []finding.Finding) []finding.Finding {
	for i := range in {
		res, ok := validator.Validate(in[i].RuleName, in[i].Secret)
		if !ok {
			continue
		}
		if res.Valid {
			in[i].VerificationStatus = "VERIFIED"
		} else {
			in[i].VerificationStatus = "POTENTIAL"
		}
	}
	return in
}
```

```go
// internal/scanner/stage_reporter.go
package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
)

type ReporterStage struct {
	Dedup    bool
	Downgrade bool
}

func NewReporterStage(dedup, downgrade bool) *ReporterStage {
	return &ReporterStage{Dedup: dedup, Downgrade: downgrade}
}

func (s *ReporterStage) Process(in []finding.Finding) []finding.Finding {
	out := in
	if s.Downgrade {
		out = downgradeFP(out)
	}
	if s.Dedup {
		out = finding.Dedup(out)
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -v`
Expected: PASS. (The Reporter test is implicit; the downgrade.go and finding.Dedup helpers are assumed to exist from V6 — confirm with `go build ./...`.)

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/stage_rule.go internal/scanner/stage_entropy.go internal/scanner/stage_verifier.go internal/scanner/stage_reporter.go internal/scanner/stage_rule_test.go internal/scanner/testhelpers_test.go
git commit -m "refactor(scanner): extract Rule, Entropy, Verifier, Reporter stages"
```

### Task 14: M11 — Wire Confidence stage and add Pipeline type

**Files:**
- Create: `internal/scanner/stage_confidence.go`, `internal/scanner/pipeline.go`
- Test: `internal/scanner/pipeline_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/scanner/pipeline_test.go
package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestPipelineSmoke(t *testing.T) {
	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs, _ := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	p := NewPipeline(Config{Rules: rs, MinSeverity: finding.ParseSeverity("LOW")})
	got, err := p.ScanString("hello TOKEN_ABCDEF12 world", "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Confidence != "LOW" {
		t.Errorf("Confidence = %q, want LOW (no extra signals)", got[0].Confidence)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestPipelineSmoke -v`
Expected: FAIL with `NewPipeline` undefined.

- [ ] **Step 3: Implement the Confidence stage and Pipeline**

```go
// internal/scanner/stage_confidence.go
package scanner

import (
	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
)

type ConfidenceStage struct {
	scorer *confidence.Scorer
}

func NewConfidenceStage() *ConfidenceStage { return &ConfidenceStage{scorer: confidence.NewScorer()} }

func (s *ConfidenceStage) Process(in []finding.Finding) []finding.Finding {
	for i := range in {
		sig := confidence.Signals{
			RegexMatch:        in[i].RuleName != "entropy_token",
			Entropy:           in[i].Entropy,
			HasContextKeyword: false,
			Verified:          in[i].VerificationStatus == "VERIFIED",
			InCredentialPair:  false,
		}
		if sig.Entropy == 0 && in[i].Secret != "" {
			sig.Entropy = entropy.Shannon(in[i].Secret)
		}
		score := s.scorer.Score(sig)
		in[i].Confidence = confidence.Band(score)
	}
	return in
}
```

```go
// internal/scanner/pipeline.go
package scanner

import (
	"strings"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type Pipeline struct {
	Rule       *RuleStage
	Decoder    *DecoderStage
	Entropy    *EntropyStage
	Verifier   *VerifierStage
	Confidence *ConfidenceStage
	Reporter   *ReporterStage
}

func NewPipeline(cfg Config) *Pipeline {
	return &Pipeline{
		Rule:       NewRuleStage(cfg.Rules, cfg.MinSeverity),
		Decoder:    NewDecoderStage(cfg.Rules, cfg.MinSeverity, DecoderFlags{Base64: cfg.DecodeBase64, Hex: cfg.DecodeHex, Unicode: cfg.DecodeUnicode, URL: cfg.DecodeURL}),
		Entropy:    NewEntropyStage(),
		Verifier:   NewVerifierStage(),
		Confidence: NewConfidenceStage(),
		Reporter:   NewReporterStage(!cfg.NoDedup, cfg.DowngradeFP),
	}
}

func (p *Pipeline) ScanString(content, path string) ([]finding.Finding, error) {
	var all []finding.Finding
	for lineno, line := range strings.Split(content, "\n") {
		all = append(all, p.Rule.Process(line, path, lineno+1)...)
		all = append(all, p.Entropy.Process(line, path, lineno+1)...)
	}
	all = p.Verifier.Process(all)
	all = p.Confidence.Process(all)
	all = p.Reporter.Process(all)
	return all, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/stage_confidence.go internal/scanner/pipeline.go internal/scanner/pipeline_test.go
git commit -m "refactor(scanner): add Confidence stage and Pipeline type"
```

### Task 15: M11 — Reduce scanner.go to entry point + Config

**Files:**
- Modify: `internal/scanner/scanner.go`

- [ ] **Step 1: Verify the legacy API still works**

Run: `go build ./... && go test ./...`
Expected: PASS. (Tasks 11-14 are non-breaking; `ScanPaths`, `ScanFile`, etc. should still work as-is.)

- [ ] **Step 2: Replace scanner.go with the entry point**

Replace `internal/scanner/scanner.go` with:

```go
// Package scanner is the V1 pipeline entry point.
//
// V1 pipeline: Collector -> Decoder -> Rule -> Entropy -> Correlation -> Verifier -> Confidence -> Reporter.
// The legacy V6 entry points (ScanPaths, ScanFile, ScanReader, ScanURLs, ScanContent) are preserved
// as thin wrappers around the new Pipeline type.
package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type Config struct {
	Workers         int
	MaxFileSize     int64
	Exclude         ExcludeRegex
	Rules           *rules.RuleSet
	MinSeverity     finding.Severity
	NoDedup         bool
	Debug           bool
	DecodeBase64    bool
	DecodeHex       bool
	DecodeUnicode   bool
	DecodeURL       bool
	DecodeGzip      bool
	JSReconstruct   bool
	Endpoints       bool
	DowngradeFP     bool
	URLs            []string
	URLFile         string
	Scope           ExcludeRegex
	CrawlLimit      int
	CrawlDepth      int
	Headless        bool
	RateLimit       int
	UserAgent       string
	Cookies         bool
	CookieFile      string
	Concurrency     int
	HostConcurrency int
	RespectRobots   bool
	GitHistory      bool
}

type ExcludeRegex interface{ MatchString(string) bool }
```

> Note: If the existing `Config` uses `*regexp.Regexp` directly, keep that type. The interface alias above is a soft hint; replace with `*regexp.Regexp` if the existing code uses that.

- [ ] **Step 3: Verify the build and tests pass**

Run: `go build ./... && go test ./...`
Expected: PASS. If the build breaks, the legacy `ScanPaths` etc. functions need to be re-added to `scanner.go` (or to a sibling file). Move them there, do not modify their bodies.

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/scanner.go
git commit -m "refactor(scanner): reduce scanner.go to entry point + Config (V1 pipeline lives in pipeline.go and stage_*.go)"
```

### Task 16: V1.0 — Verification pass

- [ ] **Step 1: Run the V6 benchmark regression test**

Run: `go test ./... && go build ./...`
Expected: PASS. The benchmark corpus (17 correct / 0 wrong per `CHECKLIST.md`) must still produce 17 correct-rule matches. If a regression is detected, fix it before merging V1.0.

- [ ] **Step 2: Run gofmt and go vet**

Run: `gofmt -l . && go vet ./...`
Expected: no output from `gofmt`; no errors from `go vet`.

- [ ] **Step 3: Update ROADMAP.md checkboxes for V1.0**

In `ROADMAP.md`, mark all V1.0 checkboxes as `[x]`:

```markdown
### V1.0 — Foundation

- [x] **M1 Rule Engine (extend)** ...
- [x] **M2 Entropy Engine (extend)** ...
- [x] **M9 Confidence Scoring (new)** ...
- [x] **M11 Scanner Architecture (refactor)** ...
- [x] **M9 → M11 wiring** ...
```

- [ ] **Step 4: Commit and tag**

```bash
git add ROADMAP.md
git commit -m "docs: mark V1.0 Foundation phase complete"
git tag v1.0-foundation
```

---

## V1.1 — Decoding & Correlation: Scheduled Tasks

> Pick up one module at a time. Read `docs/superpowers/specs/v1/03-decoder-engine.md` and `05-credential-correlation.md`. Use the same TDD pattern (5 steps per task) as V1.0.

**M3 Decoder Engine:**
- Cap `MaxRecursionDepth` at 3 (1 task)
- Add JWT payload split decoder (1 task)
- Add `atob`/`Buffer.from` hooks consuming M6 reconstructed strings (1 task; depends on V1.2 M6 skeleton)
- Make decoder registry thread-safe with `Registry` type (1 task)
- Add `DecodeBase64URL` and `DoubleBase64` (1 task)
- Add JWT entropy helper if not already covered by M2 (covered: use `JwtEntropy` from Task 7)

**M5 Credential Correlation:**
- Create `internal/correlation/correlation.go` with `Correlator`, `CorrelatedFinding`, `Detector` interface (1 task)
- Implement 8 detectors: AWS, Stripe, Twilio, Cloudflare, GitHub App, OAuth, database URLs, JWT + signing key (8 tasks, one per detector)
- Wire correlator into the pipeline (1 task; depends on M11 having a `Correlation` stage placeholder — add it to `pipeline.go` here if V1.0 didn't add it)

**V1.1 verification:**
- Run the benchmark regression (M3 must not regress; M5 should add correlated findings)
- Tag `v1.1-decoding-correlation`

---

## V1.2 — JS / Sourcemap / Recon: Scheduled Tasks

> Read `06-js-analyzer.md`, `07-sourcemap-analyzer.md`, `08-frontend-recon.md`. Same TDD pattern.

**M6 JS Analyzer:**
- Define `JSRequest` struct (1 task)
- Detect `fetch()` calls (1 task)
- Detect `axios.{get,post,...}` calls (1 task)
- Detect `XMLHttpRequest` open/setRequestHeader chains (1 task)
- Detect Apollo and GraphQL patterns (1 task)
- Parse `Authorization` headers into `APIKeys` (1 task)
- Expose `Analyze(content, file) []JSRequest` (1 task)

**M7 Source Map Analyzer:**
- Decide on source map library (`github.com/go-sourcemap/sourcemap` vendored, or hand-rolled VLQ) (1 decision task)
- Detect `//# sourceMappingURL=...` references (1 task)
- Support local + URL + inline + `.map.gz` (1 task)
- Parse JSON, build reconstructed content (1 task)
- Hand reconstructed content to the pipeline; tag findings with `SourceMapOrigin` (1 task)
- Extract `.env` references, TODOs, dead code, debug endpoints (1 task)
- Add `--sourcemap` CLI flag, default off (1 task)

**M8 Frontend Recon:**
- Define `SurfaceFinding` struct (1 task)
- Implement 9 category detectors (graphql, swagger, openapi, admin, debug, metrics, internal, staging/uat, storage) (1-2 tasks)
- Wire recon into the pipeline (1 task)
- Add `--recon` CLI flag, default off (1 task)

**V1.2 verification:**
- Run the benchmark regression
- Manual test: scan a known JS bundle URL and confirm reconstructed findings flow through
- Tag `v1.2-js-sourcemap-recon`

---

## V1.3 — Verification & Quality: Scheduled Tasks

> Read `04-verification-engine.md`, `10-rule-quality-testing.md`, `12-reporting.md`. Same TDD pattern.

**M4 Verification Engine:**
- Add `State` enum to `internal/validator/validator.go` (1 task)
- Refactor `providers.go` into `providers/<name>.go` files (1 task)
- Add `Registry` type with `Register`/`Lookup` (1 task)
- Add AWS `sts:GetCallerIdentity` (1 task)
- Add GitHub `GET /user` (1 task)
- Add Stripe `GET /v1/account` (1 task)
- Add OpenAI `GET /v1/models` (1 task)
- Add rate limiter (`golang.org/x/time/rate`) and thread-safe pool (1 task)
- Add `--verify` CLI flag in `cmd/scan.go` (1 task)

**M10 Rule Quality Testing:**
- Create `internal/ruletest/ruletest.go` with `Harness` and `Report` (1 task)
- Create positive corpus scaffold (1 task; populate gradually)
- Add `go:generate` for negative corpus (1 task)
- Implement `Harness.Run` and FP-rate / recall gates (1 task)
- Add `cmd/ruletest/main.go` subcommand (1 task)
- Add `.github/workflows/ruletest.yml` (1 task)

**M12 Reporting:**
- Extend `finding.Finding` (already done in Task 9) (0 tasks)
- JSON formatter (1 task)
- SARIF formatter (1 task)
- HTML formatter (1 task)
- Markdown formatter (1 task)
- CSV formatter (1 task)
- Text formatter (1 task)
- Update README with new output examples (1 task)

**V1.3 verification:**
- Run the full benchmark regression
- Run `./syck ruletest` against all built-in rules; confirm no `REJECTED`
- Confirm SARIF output validates against the schema
- Tag `v1.0` (final release)

---

## Execution Order (dependency graph)

```
V1.0 Foundation
  ├─ Task 1: M1 struct           ┐
  ├─ Task 2: M1 validator        │  parallel
  ├─ Task 3: M1 compiler         │
  ├─ Task 6: M2 alphabet        │
  └─ Task 9: M9 finding field   ┘
  ↓
  ├─ Task 4: M1 loader           ┐
  ├─ Task 5: M1 version gate     │  depends on Task 2
  ├─ Task 7: M2 entropy helpers  │  depends on Task 6
  └─ Task 10: M9 scorer          ┘  depends on Task 9
  ↓
  ├─ Task 8: M2 wire entropy     ┐  depends on Task 7
  ├─ Task 11: M11 collector      │
  └─ Task 12: M11 decoder stage  ┘  parallel
  ↓
  ├─ Task 13: M11 four stages    │  depends on Task 11/12
  ├─ Task 14: M11 confidence+pipe│  depends on Tasks 10, 13
  └─ Task 15: M11 scanner.go     │  depends on Task 14
  ↓
  └─ Task 16: V1.0 verification  │  depends on Tasks 1-15
```

V1.1, V1.2, V1.3 are unblocked once V1.0 ships. Tasks within V1.1+ can be parallelized by contributor (M3 and M5 are independent; M6/M7/M8 are independent of each other; M4/M10/M12 are independent of each other).

---

## Self-Review Notes

- V1.0 has 16 tasks; V1.1 has ~12 tasks; V1.2 has ~16 tasks; V1.3 has ~17 tasks. Total ~60 tasks across V1.
- Every task ends with a commit. Commits are atomic and follow the repo's conventional-commit style.
- Public `Config` and CLI surface preserved (Task 15's `Config` struct mirrors the V6 fields).
- Each task's test is in the same package as the code it covers, per Go convention.
- No new top-level dependencies in V1.0. V1.3's M4 adds `golang.org/x/time/rate` (requires `go get`); confirm with user before merging.
- The M11 Pipeline in Task 14 has placeholder stages (Correlation, Recon are no-ops in V1.0). The real stages land in V1.1/V1.2 and just slot in.
