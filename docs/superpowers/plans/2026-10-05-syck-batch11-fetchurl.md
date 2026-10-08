# SYCK Batch 11 fetchURL Pooling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Pool `fetchURL`'s scratch buffer, and prove it actually helps.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch11-fetchurl-design.md`

**Worktree:** you are working in an isolated git worktree. Touch **only** `internal/crawler/crawler.go` and its tests. Other batches are running in parallel against other worktrees — do not touch `internal/scanner/`, `internal/jsanalysis/`, or `cmd/`.

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Benchmark-gated.** §15 item 5 requires a benchmark before this ships. Measure before and after; **if pooled is not better, revert and say so.** That is a legitimate and expected outcome.
- **The `Put` must follow the string copy.** `io.ReadAll` returns a slice the caller may alias; `string(buf)` is the copy boundary. Putting first is use-after-free that `-race` will not reliably catch.
- **Cap what goes back into the pool.** A single 10MB entry pins the pool for the whole crawl.
- Gates: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./internal/crawler/ -count=1`, `go test ./internal/scanner/ -run TestParity -count=1`, `go run . ruletest` 40/40.

---

### Task 1: Baseline benchmark + aliasing test

**Files:** `internal/crawler/fetch_test.go` (or a new `fetch_pool_test.go`)

- [ ] **Step 1: Write the benchmark first.** `BenchmarkFetchURL` against an `httptest` server serving a realistic body (a few KB). Run it `-benchmem -count=5` on **unmodified** code and record `allocs/op` and `B/op` — those are the numbers the pooling must beat.

- [ ] **Step 2: Write the aliasing test.** Fetch twice through the same client, assert the first result is unchanged after the second. Against unmodified code it passes trivially (no pool). Its job is to fail if a later `Put` is misplaced — so make sure it *would* catch that: verify it fails against a deliberately-wrong early `Put`, then restore.

- [ ] **Step 3: Commit**

```bash
git add internal/crawler/
git commit -m "test(crawler): benchmark fetchURL allocation baseline; add aliasing guard"
```

### Task 2: Pool the buffer

**Files:** `internal/crawler/crawler.go`

- [ ] **Step 1: Add the pool** as a package-level `sync.Pool` returning `*[]byte`.

- [ ] **Step 2: Use it in `fetchURL`**, `Put` after the string copy, and discard buffers larger than a stated cap instead of returning them.

- [ ] **Step 3: Re-run the benchmark** on modified code, same `-benchmem -count=5`, and report both runs side by side.

- [ ] **Step 4: Verdict.** If `allocs/op` and/or `B/op` improved, keep it. If not, **revert the production change** and commit only the benchmark and aliasing test, reporting that pooling does not pay here. Do not ship a pooling change that does not pay.

- [ ] **Step 5: Commit**

```bash
git add internal/crawler/
git commit -m "perf(crawler): pool fetchURL scratch buffer (N% fewer allocs/op)"   # or:
git commit -m "chore(crawler): pooling reverted — benchmark shows no gain; keep the guard"
```

### Task 3: CHANGELOG + §15 + gates

- [ ] **Step 1: CHANGELOG** under `[Unreleased]` — record the measured before/after numbers **whichever way the verdict went**. If pooled, say so with the numbers. If reverted, say pooling was measured and did not pay, and that the §15 item stays open with a benchmark now on record.

- [ ] **Step 2: §15 item 5** — if pooled and kept, mark the item accordingly with the numbers; if reverted, update the item to record that it was measured and did not pay, so nobody re-attempts it blindly.

- [ ] **Step 3: Full gates.** `go test -race ./...` and the rest. `grep -c entropy_threshold internal/rules/builtin.yaml` still 1.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 11 fetchURL pooling verdict"
```

## Before You Begin

Questions first — ask before starting if unclear.

## Report

Write to `/home/raven/syck/.superpowers/sdd/2026-10-05-syck-batch11-fetchurl/report.md`.

Include: both benchmark runs, the verdict and its reasoning, and — if reverted — confirmation the production file is byte-identical to the base.

Reply with ONLY (under 12 lines): Status, commits, benchmark before/after, verdict, aliasing-test can-fail evidence, gates, concerns.