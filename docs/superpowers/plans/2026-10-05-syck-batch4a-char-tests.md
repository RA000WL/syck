# SYCK Batch 4a Characterization Tests & Parity Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the four untested packages real tests and build the parity harness that every later Batch 4 refactor is verified against.

**Architecture:** New test files only — no production code changes in 4a. The parity harness pins current finding output against committed golden fixtures so 4b/4c/4d can prove they changed nothing.

**Tech Stack:** Go 1.26+, `testing`, `httptest`, `os/exec` (git, skipped when absent), viper for config.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch4-refactor-design.md` (sub-batch 4a)

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- **4a is tests-only.** No production file changes. If a test forces a production fix, stop and report it instead of editing production code — that is a finding, not a task.
- Parity must be generated against the CURRENT (pre-refactor) tree and committed as the baseline.
- Tests must be hermetic: no network, no reliance on the user's `$HOME` config, no reliance on `git` being installed (skip cleanly if absent).
- Every task ends green: `go test -race ./...`, `ruletest 40/40`, `gofmt -l .` empty, `go vet`.

## Review Focus

- A fixture file containing a known secret: expect exactly the golden count, and a missing/extra finding fails parity — Task 4 pins this with a deliberate mutation check.
- Running the suite with `HOME` pointing at a directory containing a `~/.config/syck/config.json`: expect config tests to be unaffected (they must use explicit temp paths) — Task 1 pins isolation.
- A machine without `git` on PATH: expect `internal/gitscan` tests to SKIP, not fail — Task 3 pins the skip.
- `ParseOutput` with blank lines, duplicates, and trailing whitespace: expect deduped trimmed results — Task 2 pins.
- `ScanHistory` on a directory that is not a git repo: expect a clean error, not a panic — Task 3 pins.

---

### Task 1: config package tests

**Files:**
- Create: `config/config_test.go`
- Production code: **unmodified** (`config/config.go` is read-only for this task)

**Interfaces:**
- Consumes: `config.Load(configPath string) (*viper.Viper, error)`, `config.Default() Config`
- Produces: test-only

- [ ] **Step 1: Write the tests**

```go
func TestDefault(t *testing.T) {
    d := Default()
    if d.Workers != 10 || d.MaxFileSize != "5M" || d.NoColor || d.Debug {
        t.Fatalf("unexpected defaults: %+v", d)
    }
}
func TestLoadExplicitPath(t *testing.T) {
    // write {"workers": 4, "debug": true} to a temp file; Load(path); assert v.GetInt("workers")==4
    // and that unmarshalling into Config carries it
}
func TestLoadMissingPathIsNotAnError(t *testing.T) {
    // Load("/nonexistent/path/config.json") must NOT return an error
    // (viper.ConfigFileNotFoundError is swallowed by design) — pin that
}
func TestLoadMalformedFileReturnsError(t *testing.T) {
    // write invalid JSON; Load(path) must return an error
}
func TestLoadIgnoresUserHomeConfig(t *testing.T) {
    // t.Setenv("HOME", tmpdir) with a config.json present there;
    // Load(explicit path) must use the explicit path, not the home one
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./config/ -v`
Expected: PASS. These are characterization tests — they pin existing behavior and are not expected to fail, so "RED" here means "would fail if behavior regresses". Note in the report which assertions pin a *desired* behavior vs a *quirk* (e.g. `TestLoadMissingPathIsNotAnError` may be pinning an accident of viper's error type rather than a decision). If any test fails against current code, STOP and report — do not change `config.go`.

- [ ] **Step 3: No implementation step** — if a test fails, stop and report the discrepancy.

- [ ] **Step 4: Run gates**

Run: `gofmt -l config/ && go test -race ./config/ -v`
Expected: gofmt empty, tests pass

- [ ] **Step 5: Commit**

```bash
git add config/config_test.go
git commit -m "test(config): characterize Load and Default"
```

---
### Task 2: externaltools argv + ParseOutput tests

**Files:**
- Create: `internal/externaltools/tools_test.go`
- Production code: **unmodified**

**Interfaces:**
- Consumes: `(t *XTool) ParseOutput(string) []string` for Subfinder/Amass/Httpx/Katana; `ToolType`, `GetAvailableTools`, `CheckToolInstallation`
- Produces: test-only

- [ ] **Step 1: Write the tests**

```go
func TestParseOutputDedupesAndTrims(t *testing.T) {
    // input "a.example.com\n\n  b.example.com  \na.example.com\n"
    // expect exactly ["a.example.com", "b.example.com"]
}
func TestParseOutputEmptyInput(t *testing.T) {
    // "" and "\n\n" => nil or empty
}
func TestToolTypesAreDistinct(t *testing.T) {
    // each tool's Name() matches its expected ToolType; no two return the same
}
func TestCheckToolInstallationHandlesMissingBinary(t *testing.T) {
    // point PATH at an empty temp dir; every CheckToolInstallation must return false, not panic
}
func TestExtraArgsAreSplitNotShellInterpreted(t *testing.T) {
    // ToolConfig{ExtraArgs: "-x  -y"}.Exercise the arg-construction path (e.g. via a helper or by
    // documenting that Run is exec-only); assert no shell metacharacter interpretation happens.
    // If no testable seam exists without executing the binary, SAY SO in the report rather than
    // inventing one — the Run methods exec the real tools.
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/externaltools/ -v`
Expected: PASS

- [ ] **Step 3: Report which subtests are genuinely covered vs untestable-without-exec**, so 4d knows what remains unverified.

- [ ] **Step 4: Run gates**

Run: `gofmt -l internal/externaltools/ && go test -race ./internal/externaltools/ -v`
Expected: gofmt empty, tests pass

- [ ] **Step 5: Commit**

```bash
git add internal/externaltools/tools_test.go
git commit -m "test(externaltools): ParseOutput, tool identity, missing-binary handling"
```

---
### Task 3: gitscan + json_scanner tests

**Files:**
- Create: `internal/gitscan/scanner_test.go`
- Create: `internal/json_scanner/scanner_test.go`
- Production code: **unmodified**

**Interfaces:**
- Consumes: `gitscan.ScanHistory(repoPath string, cfg scanner.Config) ([]finding.Finding, error)`, `json_scanner.ScanJSONFile(path string, content string, rs *rules.RuleSet, minSev finding.Severity) []finding.Finding`
- Produces: test-only

- [ ] **Step 1: Write the gitscan tests**

```go
func TestScanHistoryFindsCommittedSecret(t *testing.T) {
    if _, err := exec.LookPath("git"); err != nil { t.Skip("git not available") }
    // temp dir: git init, write a file containing a rule-matching secret, git add + commit
    // (set user.email/user.name via -c flags or env to avoid depending on global config)
    // ScanHistory(dir, cfg) must return >= 1 finding
}
func TestScanHistoryNonRepoIsCleanError(t *testing.T) {
    if _, err := exec.LookPath("git"); err != nil { t.Skip("git not available") }
    // empty temp dir (never git init'd); expect an error, not a panic, and no findings
}
```

- [ ] **Step 2: Write the json_scanner tests**

```go
func TestScanJSONNestedSecretKey(t *testing.T) {
    // rs from rules.LoadDefault(); content with {"config":{"apiKey":"AKIA..."}} at depth 2
    // expect a finding whose RuleName is a json-scanner rule and whose File/Line are set
}
func TestScanJSONNonSecretKeyIgnored(t *testing.T) {
    // {"version":"1.2.3","name":"foo"} => no findings
}
func TestScanJSONMalformedInput(t *testing.T) {
    // invalid JSON => no panic, no findings
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/gitscan/ ./internal/json_scanner/ -v`
Expected: PASS (or SKIP for gitscan if git is absent)

- [ ] **Step 4: Run gates**

Run: `gofmt -l internal/gitscan/ internal/json_scanner/ && go test -race ./internal/gitscan/ ./internal/json_scanner/ -v`
Expected: gofmt empty, tests pass

- [ ] **Step 5: Commit**

```bash
git add internal/gitscan/scanner_test.go internal/json_scanner/scanner_test.go
git commit -m "test(gitscan,json_scanner): first coverage, hermetic"
```

---
### Task 4: Parity harness + golden fixtures

**Files:**
- Create: `internal/scanner/testdata/parity/` fixtures — a mixed-language corpus covering JS, YAML, JSON, `.env`, Go, Python (each containing at least one real rule-matching secret; keep each file small, under 40 lines)
- Create: `internal/scanner/parity_test.go`
- Create: `internal/scanner/testdata/parity/golden.txt` (generated)

**Interfaces:**
- Consumes: `scanner.ScanPaths([]string, Config) ([]finding.Finding, error)`, `rules.LoadDefault()`
- Produces: test-only. The harness supports `go test ./internal/scanner/ -run TestParity -update` to regenerate the golden file.

- [ ] **Step 1: Write the fixtures** — 6+ small files, one per language, each with a distinct secret type (AWS key, Stripe key, GitHub token, generic `.env` secret, a base64-encoded secret for the decoder path, a JWT). Keep them deterministic — no random content.

- [ ] **Step 2: Write the harness**

```go
// Regeneration: go test ./internal/scanner/ -run TestParity -update
// A flag var (`var updateParity = flag.Bool("update", false, ...)`) is preferred over
// a build tag here — say which you chose and why.

func TestParityFindingsUnchanged(t *testing.T) {
    // ScanPaths over testdata/parity with a fixed Config (Rules: rules.LoadDefault(),
    // Workers: 1 for determinism, MinSeverity: SeverityLow, NoDedup: false, DowngradeFP: true)
    // Build a canonical string: one line per finding, "<relative-file>:<line>\t<rule>\t<severity>",
    // sorted; compare to testdata/parity/golden.txt (or write it under -update)
}
```

Plus a **mutation check** proving the harness actually detects change: temporarily append one extra secret line to one fixture, assert the test FAILS, then revert. Record that proof in the report — an unverified golden test is worthless.

- [ ] **Step 3: Generate the golden file**

Run: `go test ./internal/scanner/ -run TestParity -update` (or the flag form you chose)
Expected: `golden.txt` written

- [ ] **Step 4: Prove the harness detects change** — do the mutation described in Step 2, confirm failure, revert, confirm pass. Record both outputs.

- [ ] **Step 5: Run gates**

Run: `gofmt -l internal/scanner/ && go test -race ./internal/scanner/ -run TestParity -v && go test -race ./... && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, parity PASS, all packages ok, ruletest `40 tested, 40 PASSED`

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/parity_test.go internal/scanner/testdata/parity/
git commit -m "test(scanner): parity harness + golden fixtures (baseline for 4b-4d)"
```