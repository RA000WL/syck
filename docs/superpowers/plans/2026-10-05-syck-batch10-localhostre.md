# SYCK Batch 10 localhostRE — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix the `localhostRE` under-match, and fix its anchoring in the same edit so the two changes are coherent.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch10-localhostre-design.md`

**Worktree:** you are working in an isolated git worktree. Touch **only** `internal/jsanalysis/analyze.go`, its tests, and new test files under `internal/jsanalysis/`. Other batches are running in parallel against other worktrees — do not touch `internal/scanner/`, `internal/crawler/`, `internal/recon/`, or `cmd/`.

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Vocabular and anchoring change together.** A widened token list on an unanchored regex trades under-matches for *wrong* findings.
- **Do not delegate to `internalurl.IsLoopback`.** Batch 5 declined and recorded why; after this batch it becomes closer to viable, but delegation is a separate decision. Only update the tripwire comment so it does not overstate readiness.
- **Do not touch `internal/recon`'s `classifyInternal`** — it already reports these forms.
- **Characterize before changing.** Pin current behaviour for all six inputs in the spec table first.
- Gates: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `go test ./internal/scanner/ -run TestParity -count=1`, `go run . ruletest` 40/40.

---

### Task 1: Characterize

**Files:** `internal/jsanalysis/analyze_test.go` or a new `localhost_re_test.go`

- [ ] **Step 1: Read the current regex and every place it is used** — `analyze.go` declares it and one call site consumes `FindAllStringSubmatch`. Note what the finding actually stores (the whole match? a capture group?).

- [ ] **Step 2: Pin all six inputs from the spec table**, asserting current behaviour against **unmodified** code:

  | Input | Current |
  |---|---|
  | `http://my-localhost:8080/` | reports the **subspan** `localhost:8080` — the exact defect |
  | `var db = "LOCALHOST:8080"` | nothing |
  | `var db = "127.0.0.2:8080"` | nothing |
  | `var db = "[::1]:8080"` | nothing |
  | `var db = "localhost:8080"` | reports |
  | `var db = "example.com:8080"` | nothing |

Assert the whole findings slice for each, not `contains` — added findings must fail too.

- [ ] **Step 3: Commit**

```bash
git add internal/jsanalysis/
git commit -m "test: characterize localhostRE under-match and unanchored subspan"
```

### Task 2: Fix vocabular and anchoring together

**Files:** `internal/jsanalysis/analyze.go`

- [ ] **Step 1: Anchor the match** at a token boundary so a loopback token inside a longer hostname is not carved out. Decide the boundary class from the input shapes and record the choice.

- [ ] **Step 2: Widen the vocabular**: `localhost` (any case), `127.0.0.0/8`, `::1`, `0.0.0.0`. Keep the `:port` requirement and the port shape.

- [ ] **Step 3: Verify per the spec table** — the three under-matched classes now report; `example.com:8080` still reports nothing; `localhost:8080` still reports the same thing. **`http://my-localhost:8080/` changes** — that is expected and is the anchoring fix, not a regression. Record precisely what it changes to.

- [ ] **Step 4: Update Batch 5's tripwire comment** at the `localhostRE` declaration in `analyze.go` — the comment in that block explains why delegation was declined. Now that anchoring is fixed, revise its trigger condition so it stays true, and state that delegation is *closer* but still not done.

- [ ] **Step 5: Commit**

```bash
git add internal/jsanalysis/
git commit -m "fix(jsanalysis): widen and anchor localhostRE so loopback hosts are matched whole"
```

### Task 3: CHANGELOG + §15 + gates

- [ ] **Step 1: CHANGELOG** under `[Unreleased]`. Findings go **up** for three classes. Also state the anchoring change explicitly: for a loopback token embedded in a longer hostname, the reported string changes from the carved subspan to the whole host. Users keying on the emitted substring will see a diff.

- [ ] **Step 2: §15 item 3** — close it or narrow it to whatever residue remains (e.g. delegation to `internalurl` still not done, and why).

- [ ] **Step 3: Full gates + blast radius**

`git diff --stat <base>..HEAD` — production change must be `internal/jsanalysis/analyze.go` plus nothing else.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 10 localhostRE fix"
```

## Before You Begin

Questions first — ask before starting if unclear.

## Report

Write to `/home/raven/syck/.superpowers/sdd/2026-10-05-syck-batch10-localhostre/report.md`.

Include: the new regex and the boundary class you chose and why, the before/after for all six inputs, exactly what the subspan case changes to, and gates.

Reply with ONLY (under 12 lines): Status, commits, new regex, before/after for all six, what the subspan case becomes now, gates, concerns.