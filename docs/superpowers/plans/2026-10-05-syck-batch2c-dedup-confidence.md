# SYCK Batch 2c Dedup + Confidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop post-processing from destroying triage signal — preserve per-occurrence findings, make rule attribution machine-matchable again, and collapse the two confidence scales into one.

**Architecture:** Task 1 adds a secondary finding field for machine-readable multi-rule attribution (join on demand) so existing exact-match correlator/adaptive lookups keep working. Task 2 unifies confidence on the `confidence` package (the one with the scorer and band function) and deletes the parallel `finding` constants. Task 3 refreshes adaptive + entropy-floor consistency (deferred 2b/2a items).

**Tech Stack:** Go 1.26+, Go regexp, existing `finding`/`confidence`/`adaptive`/`correlation` packages.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch2-detection-design.md` (section 2c)

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- `finding.Finding.RuleName` MUST stay a single exact rule name (8 correlator detectors do exact `RuleName != name` matching; `adaptive` weights are keyed by rule name; `correlator.Fingerprint` hashes rule name).
- Unified confidence scale = `internal/confidence` (`ptsRegex 40, ptsEntropy 20, ptsContext 15, ptsVerified 50, ptsCredPair 30`, cap 120, `Band()` thresholds ≤30 LOW / ≤60 MEDIUM / ≤90 HIGH / ≤120 CRITICAL / else VERY_HIGH). `finding.Confidence*` constants are deleted.
- Findings count is a user-visible contract: Task 1 changes it (more findings when one secret matches N rules in one file) — release-note required.
- No rule-regex changes (2b done), no decoder changes (2a done).
- Every task ends green: `go build`, `gofmt -l .` empty for touched files, `go vet` on touched packages, targeted `go test -race`, full `go test -race ./...` at the end.

## Review Focus

- Same secret at 3 lines under 2 rules: expect 3 findings (not 1), each with a single-name `RuleName` and `RuleNames` listing both: Task 1 test pins.
- Adaptive `--adaptive` run after Task 1: expect weights to apply (modifier != 0 on a penalized rule) — Task 1 pins, because a joined `RuleName` would silently zero it.
- A `MEDIUM`-confidence entropy finding before/after Task 2: expect same `ConfidenceBand` — Task 2 pins, so no triage-table churn for users.
- `env_generic_secret` (only builtin with `entropy_threshold: 3.0`) found behind a base64 blob: expect suppressed like plaintext — Task 3 pins the decoder floor.
- URL-param finding (`?token=`) with low-entropy value: expect unchanged behavior (2.0 floor stays; no Rule object exists) — Task 3 pins explicitly so the gap is intentional, not accidental.

---

### Task 1: DeduplicateBySecret preserves occurrences + attribution

**Files:**
- Modify: `internal/finding/finding.go` — add field `RuleNames []string \`json:"rule_names,omitempty"\`` to `Finding` after `RuleName`; rewrite `DeduplicateBySecret`
- Test: `internal/finding/dedup_test.go` (create; check existing `internal/finding/*_test.go` first)

**Interfaces:**
- Consumes: nothing new
- Produces: `func DeduplicateBySecret(findings []Finding) []Finding` — same signature. New behavior: group key `Secret + "\x00" + File` (unchanged) but emit **one finding per distinct occurrence (File+Line+Column)**, with `RuleName` = highest-severity rule name for that occurrence and `RuleNames` = all rule names at that occurrence (sorted by severity desc, then name asc for determinism); severity = highest across the group; stable order = by File, then Line, then Column.

- [ ] **Step 1: Write the failing tests**

```go
func TestDeduplicateBySecretPreservesLines(t *testing.T) {
    // same secret, same file, lines 10/20/30, rules r1/r2/r1 -> expect 3 findings with Lines 10,20,30
}
func TestDeduplicateBySecretRuleNames(t *testing.T) {
    // same line matched by r1(LOW) and r2(HIGH) -> 1 finding: RuleName=="r2", RuleNames==["r2","r1"] (severity desc)
}
func TestDeduplicateBySecretCrossFileKept(t *testing.T) {
    // same secret in 2 files -> 2 findings, one per file
}
func TestDeduplicateBySecretRuleNameIsSingleName(t *testing.T) {
    // assert no finding's RuleName contains ","  (correlator exact-match requirement)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/finding/ -run TestDeduplicateBySecret -v`
Expected: FAIL (today: 1 finding, Line of first occurrence, comma-joined RuleName)

- [ ] **Step 3: Implement** — add `RuleNames` field; rewrite `DeduplicateBySecret` per Interfaces block (group by secret+file, then bucket by line/column; join names for display via `RuleNames`, keep `RuleName` single).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/finding/ ./internal/correlation/ ./internal/adaptive/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/finding/finding.go internal/finding/dedup_test.go
git commit -m "fix(finding): preserve occurrences, single-name RuleName + RuleNames"
```

---
### Task 2: Unified confidence scale

**Files:**
- Modify: `internal/finding/finding.go` — delete `ConfidenceRegex/Entropy/Context/Decoded/URLParam` consts (10-16) once unused
- Modify: `internal/confidence/confidence.go` — expose the point constants needed by scan paths (export `PtsRegex`, `PtsEntropy`, `PtsContext`, `PtsVerified`, `PtsCredPair`, `EntropyFloor`, `MaxScore`) so scanner code references one package
- Modify: all scanner sites assigning confidence: `internal/scanner/helpers.go:584,602,659,684`, `internal/scanner/scan.go:642,677,701,1227`, `internal/scanner/url_secrets.go:51`, `internal/scanner/stage_confidence.go` — replace `finding.Confidence*` sums with `confidence.*` constants, and make each site set `ConfidenceBand` consistently with `confidence.Band(score)` (add band where missing)
- Test: `internal/scanner/confidence_scale_test.go` (create) + existing `internal/confidence` tests

**Interfaces:**
- Consumes: `confidence.Band(score int) string`, `confidence.Scorer`, exported point constants
- Produces: every finding carries `Confidence` (0-120 on the unified scale) and a `ConfidenceBand` from `confidence.Band`; `finding.Confidence*` constants deleted (compile-time proof no stale users)

**Mapping decision (controller-ruled, keep this):** regex rule match = `confidence.PtsRegex` (40) (+`PtsDecoded`-equivalent: no such constant exists, so a decoded finding keeps `PtsRegex` — do NOT invent new point values); entropy-only finding = `PtsEntropy + PtsContext` (35); contextual = `PtsEntropy + PtsContext`; URL-param = `PtsRegex + PtsContext` (replace the deleted `ConfidenceURLParam + ConfidenceRegex` = 70 with a principled 55); expired-JWT regex = `PtsRegex`.

- [ ] **Step 1: Write the failing tests**

```go
func TestConfidenceBandMatchesUnifiedScale(t *testing.T) {
    // a MEDIUM-band entropy finding: assert Confidence == confidence.PtsEntropy+confidence.PtsContext and ConfidenceBand == confidence.Band(same)
}
func TestNoFindingUsesLegacyScale(t *testing.T) {
    // scan a fixture mixing regex + entropy + decoded findings; assert every Confidence <= confidence.MaxScore and every band == confidence.Band(Confidence)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run 'TestConfidence' -v`
Expected: FAIL (band unset on most sites; scale differs pre-change)

- [ ] **Step 3: Implement** — export constants, update all sites, delete `finding` constants.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/confidence/ ./internal/finding/ ./internal/scanner/ ./internal/formatters/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/confidence/ internal/finding/finding.go internal/scanner/
git commit -m "refactor(confidence): unify scale, band every finding"
```

---
### Task 3: Adaptive refresh + entropy-floor consistency + gates

**Files:**
- Modify: `internal/adaptive/adaptive.go:120-128` — replace stale `highCertaintyRules` keys with names that exist in `builtin.yaml` (`aws_access_key_id`, `aws_secret_access_key`, `stripe_secret_key`, `stripe_restricted_key`, `github_personal_access_token`, `github_app_token`, `github_oauth_access_token`, `rsa_private_key`); keep the map name and `isHighCertainty` behavior
- Modify: `internal/decoder/pipeline.go` decoded-scan entropy floor — reuse the per-rule floor introduced in 2b Task 1 (the floor logic lives in `internal/scanner/helpers.go:ruleEntropyFloor`; check whether `decoder` can import it — if not, `export` it from `decoder` and have scanner call it, or duplicate with a test pinning identical behavior; state the choice in the commit body)
- Test: `internal/adaptive/adaptive_test.go` (extend if present: every `highCertaintyRules` key must exist as a rule name in `builtin.yaml` — loads rules in-test), `internal/decoder/` floor test

**Interfaces:**
- Consumes: Task 2's exported `confidence` constants (no dependency), 2b's per-rule floor behavior
- Produces: `highCertaintyRules` keys all valid; decoded-path floor honors per-rule thresholds

- [ ] **Step 1: Write the failing tests**

```go
func TestHighCertaintyRulesExistInBuiltin(t *testing.T) {
    // load rules.LoadDefault(); for each key in highCertaintyRules assert a rule with that name exists
}
func TestDecodedScanHonorsRuleEntropyThreshold(t *testing.T) {
    // base64-encode a low-entropy token matching a rule with entropy_threshold 3.0; assert no decoded finding
}
```

(`internal/adaptive` importing `internal/rules` in a test is fine — no cycle: rules imports finding only. Verify.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adaptive/ ./internal/decoder/ -run 'TestHighCertainty|TestDecodedScanHonors' -v`
Expected: FAIL (stale keys + 2.0 decoder floor)

- [ ] **Step 3: Implement** both fixes.

- [ ] **Step 4: Run full gates**

Run: `go build -o /tmp/opencode/syck-2c . && gofmt -l . && go vet ./... && go test -race ./... && go run . ruletest 2>&1 | tail -1`
Expected: build OK, gofmt empty, vet clean, all PASS, ruletest 40/40

- [ ] **Step 5: Commit**

```bash
git add internal/adaptive/ internal/decoder/ internal/scanner/
git commit -m "fix(adaptive): real high-certainty names; fix(decoder): per-rule floor"
```

---
### Task 4: Release note + docs

**Files:**
- Create: `CHANGELOG.md` (check if one exists first with `ls CHANGELOG.md`)
- Modify: `README.md` (findings/dedup wording if it describes collapse behavior), `ARCHITECTURE.md` §10 post-processing (currently missing section — add the dedup + confidence description)

- [ ] **Step 1: Write the entry** — `## [2.0.0]` (Batch 2 cumulative) documenting: decoders now opt-in reachable; per-rule entropy thresholds; rule-count 202→199 + gating; **behavior change**: cross-rule dedup now keeps one finding per occurrence (counts increase when one secret matches several rules in one file); unified confidence scale; adaptive high-certainty refresh. Note 2b/2a/2c together rather than 3 separate entries.

- [ ] **Step 2: Verify** — `gofmt -l . && go build ./... && go test ./internal/finding/ ./internal/scanner/ -count=1` (docs-only task; no Go change expected)

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md README.md ARCHITECTURE.md
git commit -m "docs: batch2 changelog, dedup/confidence docs"
```