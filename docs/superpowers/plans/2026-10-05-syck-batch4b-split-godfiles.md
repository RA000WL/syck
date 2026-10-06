# SYCK Batch 4b God-File Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the two God files along existing seams with zero behavior change, verified by the parity harness.

**Architecture:** Pure moves. Each function moves to a new file in the same package; imports get recomputed by the toolchain, not hand-edited. The parity harness is the gate: any finding drift means revert-to-last-green, not golden regeneration.

**Tech Stack:** Go 1.26+, existing `internal/scanner` and `cmd` packages, `goimports`-equivalent import fixing via `go build` feedback.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch4-refactor-design.md` (sub-batch 4b)

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- **Pure moves.** No signature changes, no logic edits, no "while I'm here" cleanups. A moved function must be byte-identical apart from its import block.
- **Parity must stay green** (`go test ./internal/scanner/ -run TestParity`) after every commit in this plan. Drift means revert, never regenerate the golden.
- `internal/scanner/scan.go` keeps its name and stays the dispatch surface; `cmd/scan.go` keeps its name.
- Every task ends green: `go build`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `ruletest 40/40`.

## Review Focus

- `TestParityFindingsUnchanged` still passes after every move — this is the only thing that proves the refactor was behavior-neutral.
- `cmd/scan.go`'s package-level `init()` still registers all flags: splitting `var (...)` and `init()` across files must not drop or reorder flag registration, or `--help` output changes and `SYCK_SCAN_*` env binding breaks.
- No symbol is duplicated or lost during the move (the compiler catches most of this, but a stale duplicate in two files would still build if one is unexported-and-unused).
- Unused imports do not survive (gofmt does not remove them; only the compiler errors).

---

### Task 1: Split `internal/scanner/scan.go`

**Files:**
- Create: `internal/scanner/scan_paths.go` — `ScanPaths`, `recordFingerprints`, `reportProgress`
- Create: `internal/scanner/scan_file.go` — `ScanBinaryFile`, `ScanFile`
- Create: `internal/scanner/scan_content.go` — `ScanContent`, `scanContent`
- Create: `internal/scanner/scan_stream.go` — `scanFileStreaming`, `scanFileFallback`
- Create: `internal/scanner/scan_read.go` — `ScanReader`
- Create: `internal/scanner/scan_urls.go` — `ScanURLs`
- Create: `internal/scanner/scan_util.go` — `isTextFile`, `baseOf`, `checkEntropyToken`, `confidenceBandFromScore`, `FilterNewOnly`, `contextLabel`, `ScanExpiredJWTs`, plus the `const`/`var` blocks currently at the top of `scan.go`
- Modify: `internal/scanner/scan.go` — becomes the dispatch surface only (package doc + the entry-point comments), or is deleted entirely if nothing but the package comment remains

**Interfaces:**
- Consumes: nothing new — every symbol keeps its exact signature
- Produces: same package, same exported symbols (`ScanPaths`, `ScanBinaryFile`, `ScanFile`, `ScanContent`, `ScanReader`, `ScanURLs`, `FilterNewOnly`, `ScanExpiredJWTs`)

**Move map** (exact, from `scan.go`'s current line numbers — verify against the file, do not trust these blindly):
- 57 `reportProgress` → scan_paths.go
- 64 `ScanPaths` → scan_paths.go
- 260 `recordFingerprints` → scan_paths.go
- 279 `ScanBinaryFile` → scan_file.go
- 292 `ScanFile` → scan_file.go
- 506 `ScanContent` → scan_content.go
- 567 `scanFileStreaming` → scan_stream.go
- 818 `scanFileFallback` → scan_stream.go
- 862 `scanContent` → scan_content.go
- 986 `ScanReader` → scan_read.go
- 1062 `ScanURLs` → scan_urls.go
- 1148–1237 (`isTextFile`, `baseOf`, `checkEntropyToken`, `confidenceBandFromScore`, `FilterNewOnly`, `contextLabel`, `ScanExpiredJWTs`) → scan_util.go
- top-of-file `const maxEndpointBuf`, `var streamingBufPool`, `var textExtensions`, `var skipDirs` → scan_util.go

- [ ] **Step 1: Record the pre-move baseline**

Run: `go test ./internal/scanner/ -run TestParity -count=1 -v && git status --short`
Expected: parity PASS, tree clean. This is the "last green" commit to revert to if a later step drifts.

- [ ] **Step 2: Create the seven new files with the mapped functions**

Use `sed -n '<start>,<end>p'` range extraction to move each function body verbatim — do not retype it. Then run `go build ./...` and let the compiler tell you which imports each new file needs; add only those.

- [ ] **Step 3: Reduce `scan.go` to the dispatch surface** — remove the moved code, keep the package comment and any doc comments on the entry points. If the file becomes empty except the package clause, delete it instead.

- [ ] **Step 4: Verify no symbol was lost or duplicated**

Run: `go build ./... && go vet ./internal/scanner/ && gofmt -l internal/scanner/`
Expected: build OK, vet clean, gofmt empty

- [ ] **Step 5: Verify behavior is unchanged**

Run: `go test ./internal/scanner/ -run TestParity -count=1 -v`
Expected: PASS — byte-identical output. **If it FAILS, revert to the last-green commit. Do not regenerate the golden.**

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/
git commit -m "refactor(scanner): split scan.go into per-mode files (pure move)"
```

---
### Task 2: Split `cmd/scan.go`

**Files:**
- Create: `cmd/scan_config.go` — the `var (...)` flag block (lines 59-138), the `errExit*` sentinels, `scanCmd` definition, `init()`, `clampWorkers`, `parseSize`, `loadWordlist`, `parseExcludeDir`
- Create: `cmd/scan_run.go` — `runScan`
- Create: `cmd/scan_postprocess.go` — only if a clean seam exists inside `runScan` (the post-dedup/filter/validate/webhook/fail-on tail). **If `runScan` does not split cleanly without editing logic, leave it whole** — that is explicitly allowed; report which way you went and why.
- Modify: `cmd/scan.go` — reduced to what remains

**Interfaces:**
- Consumes: nothing new
- Produces: identical CLI behavior — same flags, same defaults, same `SYCK_SCAN_*` binding (which depends on `init()` still registering every flag on `scanCmd`)

- [ ] **Step 1: Record the CLI surface baseline**

Run: `go run . scan --help > /tmp/opencode/4b-help-before.txt 2>&1; wc -l /tmp/opencode/4b-help-before.txt`
Expected: captures the current `--help` output. You will diff against it in Step 4.

- [ ] **Step 2: Create `cmd/scan_config.go`** with the flag vars, sentinels, `scanCmd`, `init()`, and the four helpers moved verbatim.

- [ ] **Step 3: Create `cmd/scan_run.go`** with `runScan` moved verbatim. Attempt the `scan_postprocess.go` split only if it is a clean cut; otherwise say so in the report and keep `runScan` whole.

- [ ] **Step 4: Verify the CLI surface is byte-identical**

Run: `go run . scan --help > /tmp/opencode/4b-help-after.txt 2>&1; diff /tmp/opencode/4b-help-before.txt /tmp/opencode/4b-help-after.txt && echo "HELP IDENTICAL"`
Expected: `HELP IDENTICAL`. A diff means a flag was dropped or reordered in the move — fix before committing.

- [ ] **Step 5: Verify build and parity**

Run: `go build ./... && go vet ./cmd/ && gofmt -l cmd/ && go test ./internal/scanner/ -run TestParity -count=1`
Expected: all clean, parity PASS

- [ ] **Step 6: Commit**

```bash
git add cmd/
git commit -m "refactor(cmd): split scan.go into config/run files (pure move)"
```

---
### Task 3: Full gates + docs touch-up

**Files:**
- Modify: `ARCHITECTURE.md` §3 (Directory Layout) and §7 (Package Map) — the scanner and cmd entries currently describe single large files; update them to name the new files.

**Interfaces:**
- Consumes: Tasks 1-2
- Produces: docs matching the new layout

- [ ] **Step 1: Update the docs** to match the new file layout. Keep it accurate and brief — list the new files with one-line responsibilities. Do not restructure anything else.

- [ ] **Step 2: Full gates**

Run: `gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, build OK, vet clean, all tests pass, ruletest `40 tested, 40 PASSED`

- [ ] **Step 3: Confirm the refactor achieved its goal**

Run: `wc -l internal/scanner/scan*.go cmd/scan*.go`
Expected: no single file in the `internal/scanner` package exceeds ~350 lines; `cmd/scan_run.go` is the largest remaining file. Report the numbers.

- [ ] **Step 4: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: reflect split scanner and cmd file layout"
```