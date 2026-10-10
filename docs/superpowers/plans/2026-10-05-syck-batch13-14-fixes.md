# SYCK Batches 13–14 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch13-14-fixes-design.md`

**Worktree:** isolated. Batch 13 touches `cmd/`; Batch 14 touches `internal/scanner/` and `internal/confidence/`. They are disjoint — see the note in each task.

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- Do not change `internal/rules/builtin.yaml`. `grep -c entropy_threshold` must stay 1.
- Do not change any point value in `internal/confidence/confidence.go`.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `go test ./internal/scanner/ -run TestParity -count=1`, `go run . ruletest` 40/40.

---

### Task 1 (Batch 13): `--param-brute` honours `--severity`

**Files:** `cmd/scan_run.go` (the `--param-brute` loop, ~:450-469)

- [ ] **Step 1: Characterize.** Write a test using an `httptest` server (follow the existing crawler/`fetch_test.go` style) that reflects a parameter, driven with `MinSeverity` at CRITICAL. Assert current behaviour: the finding appears. Confirm it fails in the sense that matters — i.e. it documents the bypass.

- [ ] **Step 2: Filter at the append.** Apply `cfg.MinSeverity` to the finding before appending. Do **not** move the filter into `internal/parambrute` — the package has no severity notion of its own and the caller maps `ParamFinding` to severity, so the floor is the caller's concern. Record that reasoning at the site.

- [ ] **Step 3: Verify the floor still keeps what it should.** `Interesting` → HIGH and `Reflected` → MEDIUM. Under `--severity HIGH` an interesting parameter must still appear. Assert all three severities against both floors.

- [ ] **Step 4: Commit**

```bash
git add cmd/
git commit -m "fix(cmd): apply --severity to --param-brute findings

The append happened after collection with no floor check, so a CRITICAL
floor still printed INFO-severity hidden parameters. Batch 12 closed this
same invariant for correlation; this is the call site it left open."
```

---

### Task 2 (Batch 14): wire the credential-pair confidence signal

**Files:** `internal/scanner/stage_confidence.go`, `internal/scanner/correlation_wiring.go` or `internal/scanner/correlation_wiring_test.go` for the test

- [ ] **Step 1: Establish whether this is live.** `ConfidenceStage` is on the test-only `Pipeline`. Read `pipeline.go` and grep `NewPipeline`'s callers. **If it never runs on the CLI, say so and do not claim a user-visible delta.**

- [ ] **Step 2: Decide the predicate.** `DetectionMethod == "correlation"` marks every correlated finding, including `database_url_with_credentials`, which has **one** component and is not a pair. Decide whether the pair bonus should apply to it, record the reasoning, and make the test assert the decision.

- [ ] **Step 3: Set the signal from the finding.** Replace the hardcoded `false` with the predicate. Do not change any point value.

- [ ] **Step 4: Assert the number.** A two-component correlated finding's score must include the 30 points; a one-component one must not (or must, per your Step 2 decision). Assert the exact score.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/ internal/confidence/
git commit -m "fix(scanner): set InCredentialPair from the finding instead of hardcoding false"
```

---

### Task 3: CHANGELOG + gates

- [ ] **Step 1: CHANGELOG** under `[Unreleased]`. Both entries, each stating direction: Batch 13 removes findings that a severity floor should have excluded; Batch 14 changes correlated findings' confidence — and says plainly whether it is live on the CLI.

- [ ] **Step 2: Full gates + blast radius.** `git diff --stat <base>..HEAD` — production change confined to the named files. `grep -c entropy_threshold` still 1.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: record Batches 13-14"
```

## Before You Begin

Questions first — ask before starting if unclear.

## Report

Write to `/home/raven/syck/.superpowers/sdd/2026-10-05-syck-batch13-14/report.md`.

Reply with ONLY (under 12 lines): Status, commits, Batch 13 before/after + floor-keeps-what-it-should evidence, Batch 14 live-or-not + predicate decision + exact score, gates, concerns.