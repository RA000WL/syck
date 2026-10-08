# SYCK Batch 7 Dedup-Key Truncation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Remove all 9 dedup-key truncations so distinct secrets are never merged. Findings go up, never down.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch7-dedup-keys-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Deletion only.** Remove the 9 `if len(key) > N { key = key[:N] }` blocks. No signature changes, no new helpers, no new imports.
- **Characterize before changing**, with a colliding pair that the current code merges. A test that passes before the fix proves nothing.
- **The still-merged case must keep passing.** Identical secrets across two passes report once — assert that too, so this is proven to un-merge rather than to un-dedup.
- Do not touch `internal/rules/builtin.yaml`.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, parity PASS, `go run . ruletest` 40/40.

---

### Task 1: Characterize the merge, then delete the 8 scanner truncations

**Files:**
- Create: characterization test(s) covering the Secret-only skip-sets
- Modify: `internal/scanner/scan_stream.go` (2 sites), `scan_file.go` (2), `helpers.go` (3), `scan_content.go` (1)

- [ ] **Step 1: Build a colliding pair and watch it merge**

Two distinct secrets sharing a 60+ character prefix. Long `firebase_fcm_key`-shaped values diverging after char 60 work — check what that rule's pattern actually matches before inventing values, and measure the shared-prefix length rather than assuming it.

Drive them through a path that exercises a truncated skip-set (e.g. a gzip file scanned both raw and decoded, or content scanned with decoders on). Assert the current behavior: **one** finding. Confirm it fails in the sense that matters — i.e. it documents the merge, not the fix.

- [ ] **Step 2: Delete all 8 blocks**

Remove each `if len(key) > 60 { key = key[:60] }`. Leave the map logic untouched.

- [ ] **Step 3: Assert un-merged but still deduped**

The colliding pair now reports **two**. The identical secret in both passes still reports **one**. Update only the merge assertions — if a still-merged case changes, stop and report.

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/
git commit -m "fix(dedup): stop truncating Secret-only skip-set keys at 60 chars

Two distinct secrets sharing a 60-char prefix were merged into one finding.
Full keys un-merge them; identical secrets still dedup."
```

---

### Task 2: The gitscan site

**Files:**
- Modify: `internal/gitscan/scanner.go:60-63`
- Test in `internal/gitscan/`

**This site is different.** Its key is `RuleName + ":" + Secret` truncated at **80**, and it dedups **across commits** rather than across two passes over one file. The collision surface is wider (the rule name eats 16+ chars, so secrets need share only ~60).

- [ ] **Step 1: Characterize with a two-commit repo**

Build a repo where commit 1 adds secret A and commit 2 adds secret B, A and B distinct but sharing a long prefix such that `RuleName+":"+Secret` collides at 80 chars. Assert current behavior: one finding. Follow the existing `scanner_test.go` repo-building style.

- [ ] **Step 2: Delete the truncation, verify, commit**

Remove the `if len(key) > 80` block. Assert two findings for A+B, and still one finding when the same secret appears in both commits.

```bash
git add internal/gitscan/
git commit -m "fix(dedup): stop truncating the cross-commit dedup key at 80 chars"
```

---

### Task 3: CHANGELOG + §15 + gates

**Files:**
- Modify: `CHANGELOG.md`, `ARCHITECTURE.md` §15

- [ ] **Step 1: CHANGELOG under `[Unreleased]`**

Record that distinct secrets sharing long prefixes, previously merged into one finding, now appear separately — findings go **up**. Name both key shapes.

- [ ] **Step 2: §15**

Remove or close whatever entry covers this (check whether one exists; if the truncation was never given its own §15 number, say so rather than inventing one).

- [ ] **Step 3: Full gates + blast-radius check**

`gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`

`git diff --stat <batch7-base>..HEAD` — production changes must be deletions of truncation blocks plus nothing else.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 7 dedup-key fix"
```