# SYCK Batch 12 Wire Correlation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Run `internal/correlation`'s 8 detectors on the V6 scan path so credential pairs are reported — with the severity, `--severity`, and confidence-band defects fixed as part of the same edit.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch12-correlation-design.md`

**Worktree:** you are working in an isolated git worktree. Touch `internal/scanner/`, `cmd/`, and `internal/correlation/` **only if the fix requires it**.

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Findings go UP.** This adds a kind of finding; it removes nothing.
- **Fix the three defects the spec names as part of this edit, not after:** zero severity, `--severity` bypass, off-band `VERY_HIGH`.
- **Do not add the five missing rule sets** (`cloudflare_*`, `github_app_*`, `jwt`/`jwt_signing_key`, `oauth_*`). Record that 5 of 8 detectors are dead because their components do not exist. New detection rules are a separate decision.
- **Read `DatabaseURLDetector` before assuming the shape** — `detector_database_url.go` is not a `matchPair` and may need different handling.
- Characterize before changing.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `go test ./internal/scanner/ -run TestParity -count=1`, `go run . ruletest` 40/40.

---

### Task 1: Characterize what a correlated finding looks like today

**Files:** new test file under `internal/scanner/`

- [ ] **Step 1: Read the parts first** — `CorrelationStage.Process`, `internal/correlation/helpers.go`'s `matchPair`, `DatabaseURLDetector`, `finding.Severity`'s zero value, `confidence.Band`, and where `MinSeverity` is applied (`helpers.go:547` and the sub-scanner calls) versus where findings are collected.

- [ ] **Step 2: Pin the current behaviour of `CorrelationStage.Process`**: what `Severity`, `Confidence`, `ConfidenceBand`, `RuleName`, `Secret`, and `Context` a pair produces. Assert the actual values, so the three defects are documented rather than described.

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/
git commit -m "test: characterize correlated findings and the three defects they carry"
```

### Task 2: Fix the three defects inside the correlation emit

**Files:** `internal/scanner/` (the stage or its replacement), `cmd/` for the flag

- [ ] **Step 1: Derive severity from the components** — `max(a.Severity, b.Severity)` — so `--severity` has something to filter on. Record why derivation rather than a constant.

- [ ] **Step 2: Apply `MinSeverity` to correlated findings.** The cleanest place depends on where you hook in; if the hook is post-collection, the filter has to be applied there explicitly. State where and why.

- [ ] **Step 3: Derive the band from the components' confidence scores** via `confidence.Band(...)`, so the field uses the vocabulary `Band()` can actually produce. Never pass `matchPair`'s `"VERY_HIGH"` through.

- [ ] **Step 4: Add the `--no-correlation` opt-out flag** and the config plumbing, default on.

- [ ] **Step 5: Verify with the spec's five characterization cases** — pair in span reported, pair out of span not reported, single component not reported, `--severity CRITICAL` still filters, `--no-correlation` silences.

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/ cmd/
git commit -m "feat(scanner): correlate credential pairs on the scan path"
```

### Task 3: CHANGELOG + §15 + gates

- [ ] **Step 1: CHANGELOG** under `[Unreleased]`. Findings go **up**. Name the three kinds that can actually fire, state plainly that 5 of 8 detectors are dead because their component rules do not exist, and record the severity/`--severity`/band fixes as part of the same change.

- [ ] **Step 2: §15** — check whether the "correlation never runs on the CLI" gap was ever numbered. If it was, close it; if not, add it as a CLOSED entry with the dead-detector residual, following the no-compaction policy.

- [ ] **Step 3: Full gates + blast radius.** `git diff --stat <base>..HEAD`. `grep -c entropy_threshold internal/rules/builtin.yaml` must still be 1 — you must not have added rules.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 12 correlation wiring"
```

## Before You Begin

Questions first — ask before starting if unclear.

## Report

Write to `/home/raven/syck/.superpowers/sdd/2026-10-05-syck-batch12-correlation/report.md`.

Include: the before/after for each of the spec's five cases, what `DatabaseURLDetector` turned out to need, the three defect fixes with evidence, and gates.

Reply with ONLY (under 14 lines): Status, commits, five cases before/after, three defects fixed, DatabaseURLDetector handling, how many detectors can fire, gates, concerns.