# SYCK Batch 9 Multiline Filters — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Give `internal/scanner/multiline.go` the filters every other rule-matching path already has, without re-introducing Batch 8's PEM suppression.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch9-multiline-design.md`

**Worktree:** you are working in an isolated git worktree. Touch **only** `internal/scanner/multiline.go`, `internal/scanner/multiline_test.go`, and new test files under `internal/scanner/`. Other batches are running in parallel against other worktrees — do not touch `internal/jsanalysis/`, `internal/crawler/`, or `cmd/`.

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Mirror `internal/scanner/helpers.go:529-564` order**: `RequiresContext` first (it needs the text), then secret extraction, then the entropy floor, then `IsFalsePositiveSecret` → `IsFalsePositiveToken` → `IsFalsePositiveEmail`.
- **`IsFalsePositiveToken` must be exempted for multi-line spans.** Batch 8 found this on the decoded path: a PEM block is nothing but hyphens and base64, and Token's hyphen heuristic (`>= 3` hyphens, `len > 20`, aimed at feature-flag names) cannot tell one from a flag. Without the exemption this batch suppresses the CRITICAL private-key rules on a default-on path — the single worst outcome available here.
- **Characterize before changing.** The PEM-block test must be written first and observed passing (it documents that the current code reports it), then the filters' effect measured.
- Do not touch `internal/rules/builtin.yaml`.
- Gates: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `go test ./internal/scanner/ -run TestParity -count=1`, `go run . ruletest` 40/40.

---

### Task 1: Characterize

**Files:** `internal/scanner/multiline_test.go` or a new `multiline_filter_test.go`

- [ ] **Step 1: Read `multiline.go` and `ScanMultiLine`'s callers** — note what text is available for a context check and how the window is built.

- [ ] **Step 2: Pin current behavior**

Three cases, asserted against **unmodified** code:

  a. A **full PEM block** (`-----BEGIN RSA PRIVATE KEY-----` + fabricated base64 body + `-----END RSA PRIVATE KEY-----`) — must be reported. Use a fabricated body, never a real key. This is the guard against re-introducing Batch 8's suppression.
  b. A **kubeconfig token** and a **docker-compose secret** shape — record whether reported (likely yes); these are the probable survivors.
  c. A shape the FP filters *should* reject. The multi_line rules match structured content, so constructing one needs thought — a placeholder-value or hyphen-dense multi-line span. If you cannot construct one that any filter rejects, **say so** rather than forcing it; that is a legitimate finding about this path, not a failure.

Record measured entropy for each span so the floor's effect is visible rather than inferred.

- [ ] **Step 3: Commit**

```bash
git add internal/scanner/multiline_test.go
git commit -m "test: characterize multiline.go's unfiltered rule matching"
```

### Task 2: Add the filters

**Files:** `internal/scanner/multiline.go`

- [ ] **Step 1: Add `RequiresContext` + the entropy floor + the three FP filters**, in `helpers.go` order, context text = the multi-line window `content`.

- [ ] **Step 2: Exempt `IsFalsePositiveToken` for multi-line spans**, with a comment naming the PEM reason and pointing at Batch 8's decoder carve-out as the precedent.

- [ ] **Step 3: Record that `RequiresContext` is a no-op today.** None of the 9 `multi_line` rules sets it. One sentence in the comment, so a future reader does not expect suppression.

- [ ] **Step 4: Verify**

The PEM block still reports. Kubeconfig/docker-compose survivors still report. Any FP-shaped case is suppressed. **If the PEM block stops being reported, stop and report** — that is the defect this batch exists to avoid.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/multiline.go
git commit -m "fix(scanner): apply entropy floor and FP filters on the multiline path"
```

### Task 3: CHANGELOG + §15 + gates

- [ ] **Step 1: CHANGELOG** under `[Unreleased]` — false-positive reduction, findings go down, with measured counts. State the Token exemption and why (PEM preservation) explicitly.

- [ ] **Step 2: §15 item 7** — narrow it to record that multiline.go is now covered and what remains (nothing, if this is the last path). Check whether the item should be closed or narrowed to a residual.

- [ ] **Step 3: Full gates + blast radius**

`git diff --stat <base>..HEAD` — production change must be `internal/scanner/multiline.go` plus nothing else. Confirm `grep -c entropy_threshold internal/rules/builtin.yaml` is still 1.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 9 multiline filter adoption"
```

## Before You Begin

Questions first — ask before starting if unclear.

## Report

Write to `<worktree>/.superpowers/... ` **no** — write to `/home/raven/syck/.superpowers/sdd/2026-10-05-syck-batch9-multiline/report.md`, which is on `main`'s worktree and readable by the coordinator.

Include: measured entropies, before/after per fixture, the PEM-survival evidence, and gates.

Reply with ONLY (under 12 lines): Status, commits, PEM still reported (evidence), before/after counts, what you could not construct and why, gates, concerns.