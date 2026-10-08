# SYCK Batch 8 FP Filters on Lagging Paths — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Apply the plain-file path's FP and context filters to the three lagging paths that already have entropy floors. Findings go **down** (false positives removed).

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch8-fp-filters-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Suppression only.** Every filter added here removes findings; none adds. If any finding appears that was not there before, stop and report.
- **Characterize before changing, per path.** Each path gets tests pinning current behavior with FP-shaped and context-less inputs, so the delta is measured.
- **Do not touch `multiline.go`** (Batch 9), `url_secrets.go`, or the `json_scanner` key-name heuristic branch.
- **`decoder/pipeline.go` already has Token/Email** — add only `IsFalsePositiveSecret` and `RequiresContext` there.
- Do not touch `internal/rules/builtin.yaml`.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, parity PASS, `go run . ruletest` 40/40.

---

### Task 1: Characterize all three paths

**Files:**
- Create: `internal/jsrecon/fp_filter_test.go`
- Create: `internal/json_scanner/fp_filter_test.go`
- Create: `internal/decoder/fp_filter_test.go`

- [ ] **Step 1: Read each call site and its surroundings**

`internal/jsrecon/reconstruct.go:402-430`, `internal/json_scanner/scanner.go:95-120`, `internal/decoder/pipeline.go:155-180`. For each, note what text is available for a context-keyword check — there may be no natural "line".

- [ ] **Step 2: Write the characterization tests**

For each path, drive it with:
  - an input producing a finding whose secret matches an FP heuristic (check what `IsFalsePositiveSecret`/`Token`/`Email` actually reject first — read `internal/entropy/entropy.go:355-490` rather than guessing)
  - a context-less `env_generic_secret` match (it sets `requires_context: true`)
  - controls that must survive both before and after (a high-entropy secret with context keywords nearby)

Assert **current** behavior: all reported. Record the exact inputs and why each is FP-shaped or context-less.

- [ ] **Step 3: Verify and commit against unmodified code**

```bash
git add internal/jsrecon/fp_filter_test.go internal/json_scanner/fp_filter_test.go internal/decoder/fp_filter_test.go
git commit -m "test: characterize missing FP and context filters on the three lagging paths"
```

---

### Task 2: Add the missing filters

**Files:**
- Modify: `internal/jsrecon/reconstruct.go`
- Modify: `internal/json_scanner/scanner.go` (ruleset branch only — **not** the key-name heuristic at ~:71)
- Modify: `internal/decoder/pipeline.go` (add `IsFalsePositiveSecret` + `RequiresContext` only)

- [ ] **Step 1: Mirror the helpers.go filter order**

`RequiresContext` first (it needs the source text, before secret extraction narrows it), then after secret extraction and the entropy floor: `IsFalsePositiveSecret`, `IsFalsePositiveToken`, `IsFalsePositiveEmail`. Match `helpers.go:529-564` ordering so the three paths read the same.

- [ ] **Step 2: Decide the context-check text per path and record it**

State in a comment at each site what text the `RequiresContext` check runs against and why. If a path has no natural line, say what substitutes for it.

- [ ] **Step 3: Verify suppression-only**

The characterization tests' FP/context-less cases now produce **no** finding; controls still produce one. **If any new finding appears anywhere, stop and report** — these filters cannot add by construction, so a new finding means the edit is wrong.

- [ ] **Step 4: Commit**

```bash
git add internal/jsrecon/reconstruct.go internal/json_scanner/scanner.go internal/decoder/pipeline.go
git commit -m "fix(detection): apply FP and context filters on jsrecon, json_scanner, and decoded paths"
```

---

### Task 3: CHANGELOG + §15 + gates

**Files:**
- Modify: `CHANGELOG.md`, `ARCHITECTURE.md` §15 item 7

- [ ] **Step 1: CHANGELOG under `[Unreleased]`**

Frame as **false-positive reduction** with measured counts per path: what was suppressed, what survives. Findings go down — state that plainly.

- [ ] **Step 2: Update §15 item 7**

Record which paths are now covered and which remain (`multiline.go` → Batch 9). Do not close the item if multiline is still open — reword it to name exactly what is left.

- [ ] **Step 3: Full gates + blast-radius check**

`gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`

`git diff --stat <batch8-base>..HEAD` — production changes must be filter additions at the three sites plus nothing else. `grep -c entropy_threshold internal/rules/builtin.yaml` must still be 1.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 8 FP-filter adoption; narrow the section 15 item"
```