# SYCK Batch 4d Dead Code & Duplication Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove verified dead code and collapse verified duplication. **Zero behavior change.**

**Scope note:** this plan contains only items whose grounding was verified by reading the code. Three items from the original 4d queue were checked and found **not real** and are excluded (see "Ruled out" below). The entropy-floor unification is a **behavior change** and was split into its own batch.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch4-refactor-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Zero observable behavior change.** Every task here must be provably output-identical. Parity harness green after every commit.
- **Delete nothing that is not provably unreferenced.** Task 1's and Task 4's deletions each require a `grep` proving zero references, recorded in the report.
- **Do not unify things that are deliberately different.** Task 3 is the case to watch: `parambrute`'s concurrency default is intentionally not `NumCPU`.
- Every task ends green: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, parity PASS, `go run . ruletest` 40/40.

## Ruled out by grounding — do not "fix" these

These were on the 4d queue and were checked against the code. They are **not** defects:

- **`crawler.visitedCount` is not dead.** It is exercised by the white-box race test at `internal/crawler/crawler_test.go:136,161-162`. Deleting it would delete test coverage of the visited-map synchronization.
- **`ConfidenceStage` is not drifting.** `internal/scanner/stage_confidence.go:16-24` deliberately rescores only when `Confidence == 0`, with a comment explaining that a scan site with more inputs than the stage can see already set the score, and that re-deriving the band would let band and number disagree. That is a considered design, not an oversight.
- **`crawler` has no literal-`10` worker clamp.** The 4d queue said "parambrute/crawler"; only parambrute has one.

---

### Task 1: Delete the dead `crawler.BodyPool`

**Files:**
- Modify: `internal/crawler/encoding.go` — remove the `BodyPool` var and its doc comment

**Interfaces:**
- Consumes: nothing
- Produces: nothing. Pure deletion of a package-level symbol.

`BodyPool` is declared at `internal/crawler/encoding.go:13-14` with the comment "reuses response body buffers to reduce GC pressure". Grep finds **no reference anywhere** in the repository — not in `encoding.go`, not in `crawler.go`, not in any test. It is a `sync.Pool` that nothing ever Gets from or Puts to, so it holds no buffers and does nothing.

- [ ] **Step 1: Prove it is unreferenced**

Run: `grep -rn "BodyPool" --include=*.go .`
Expected: exactly two hits, both the declaration and its own doc comment, both in `encoding.go`.

**If any other hit appears, stop and report it.** A live `BodyPool` means this item is not dead code and the deletion must not happen.

- [ ] **Step 2: Delete the var and its comment**

Delete the comment lines and the `var BodyPool = sync.Pool{...}` block. Then check whether `sync` is still imported for anything else in the file — if not, remove the import. The compiler will tell you; gofmt will not.

- [ ] **Step 3: Verify and commit**

Run: `go build ./... && go vet ./internal/crawler/ && gofmt -l internal/crawler/ && go test -race ./internal/crawler/ -count=1 && go test ./internal/scanner/ -run TestParity -count=1`
Expected: all clean, parity PASS.

```bash
git add internal/crawler/encoding.go
git commit -m "refactor(crawler): delete unused BodyPool (declared, never referenced)"
```

---

### Task 2: Collapse the duplicated SQLite pragma setup

**Files:**
- Create: `internal/sqliteutil/sqliteutil.go` — one `Open(path string) (*sql.DB, error)` that does `sql.Open` plus the pragma block
- Create: `internal/sqliteutil/sqliteutil_test.go`
- Modify: `internal/correlator/cache.go` — call `sqliteutil.Open`
- Modify: `internal/crawler/urlcache.go` — call `sqliteutil.Open`

**Interfaces:**
- Consumes: nothing
- Produces: `sqliteutil.Open(path string) (*sql.DB, error)`

**Why this is duplication and not coincidence.** Two packages each open a SQLite database and each apply the same tuning, with the same values and a near-identical comment:

| | `internal/correlator/cache.go` | `internal/crawler/urlcache.go` |
|---|---|---|
| `SetMaxOpenConns(1)` | yes | yes |
| `SetMaxIdleConns(1)` | yes | yes |
| `PRAGMA journal_mode=WAL` | yes | yes |
| `PRAGMA busy_timeout=5000` | yes | yes |
| errors ignored | yes (documented) | yes (documented) |

Both comments explain the same reasoning: crawl/scan workers write from many goroutines, so a single-writer cap plus WAL plus a busy timeout turns a contended write into a wait instead of an instant `SQLITE_BUSY`, and a read-only database file cannot switch journal mode so the error must be ignored rather than turned into a failure. That is one piece of reasoning written twice, and `busy_timeout=5000` is a tuning constant that now has two places to change.

**Placement:** `internal/sqliteutil` is a leaf — it imports `database/sql` and `modernc.org/sqlite` and nothing from `syck`. It must not import `correlator` or `crawler`, and neither of those may import each other.

- [ ] **Step 1: Write the test first**

Assert that `Open` returns a usable `*sql.DB` and that the pragmas took effect — `PRAGMA journal_mode` is `wal` and `PRAGMA busy_timeout` is `5000` — mirroring the assertions `internal/correlator/cache_test.go:327-336` already makes. Copy that assertion style; do not invent a new one.

- [ ] **Step 2: Implement `Open`**

Move the pragma loop and the `SetMaxOpenConns(1)` / `SetMaxIdleConns(1)` calls verbatim, keeping the "best-effort, errors deliberately ignored" rationale in the doc comment. `Open` returns the `*sql.DB` and an error only from `sql.Open` itself — a pragma failure must not become an error, because that is the current behavior and changing it would change behavior for a read-only database file.

- [ ] **Step 3: Switch both call sites**

Replace each package's inline block with `sqliteutil.Open(path)`, keeping each package's own error wrapping (they differ: `"open url cache db: %w"` vs the correlator's own wording). Keep their table-creation code untouched.

- [ ] **Step 4: Verify and commit**

Run: `go build ./... && go vet ./... && gofmt -l . && go test -race ./internal/correlator/ ./internal/crawler/ ./internal/sqliteutil/ -count=1 && go test ./internal/scanner/ -run TestParity -count=1`
Expected: all clean, parity PASS. `internal/correlator`'s existing pragma assertions must still pass unchanged — they are the proof the extraction preserved behavior.

```bash
git add internal/sqliteutil/ internal/correlator/cache.go internal/crawler/urlcache.go
git commit -m "refactor(sqlite): single-source WAL/busy_timeout/single-writer setup"
```

---

### Task 3: Name `parambrute`'s concurrency default, and say why it is not `EffectiveWorkers`

**Files:**
- Modify: `internal/parambrute/parambrute.go` — extract the literal `10` into a named constant with a doc comment

**Interfaces:**
- Consumes: nothing
- Produces: an unexported constant. No exported surface change.

**Read this before touching it.** `internal/parambrute/parambrute.go` uses the literal `10` twice — `DefaultConfig`'s `Concurrency: 10` at line 153, and the `<= 0` fallback `cfg.Concurrency = 10` at line 169. Meanwhile the scanner uses `scanner.EffectiveWorkers` (`internal/scanner/workers.go:13`), which falls back to `max(runtime.NumCPU(), 2)`.

**These are deliberately different and must not be unified.** `EffectiveWorkers` sizes a **CPU-bound** pool; parambrute issues **network** requests, where `NumCPU` is a poor predictor of a good request concurrency and a fixed modest number is the safer default. Forcing parambrute onto `EffectiveWorkers` would make its default change with the host's core count — a behavior change, and a probably-worse one.

Also note `parambrute` should not import `internal/scanner` to reach that helper: `scanner` is one of the largest packages in the repo, and importing all of it for a five-line function is worse coupling than a duplicated literal.

So the fix is to remove the *duplication*, not the difference:

- [ ] **Step 1: Extract the constant**

Declare one unexported constant, e.g. `defaultConcurrency = 10`, and use it at both sites. Add a doc comment that states the value is a fixed default because the work is network-bound, and explicitly records that this is intentionally **not** `scanner.EffectiveWorkers`'s `NumCPU`-based fallback, with the reason.

- [ ] **Step 2: Verify no behavior change**

Run: `go build ./... && go test -race ./internal/parambrute/ -count=1 && go vet ./internal/parambrute/`
Expected: green. The resolved concurrency for any input must be unchanged — this is a rename plus a comment.

- [ ] **Step 3: Commit**

```bash
git add internal/parambrute/parambrute.go
git commit -m "refactor(parambrute): name the concurrency default; record why it is not NumCPU-based"
```

---

### Task 4: Delete the `cmd/scan.go` stub and fix the stale flag count

**Files:**
- Delete: `cmd/scan.go` (one line: `package cmd`)
- Modify: `ARCHITECTURE.md` line 77

**Interfaces:**
- Consumes: nothing
- Produces: nothing

`cmd/scan.go` is a one-line package clause left behind when Batch 4b split the 849-line file into `scan_config.go` and `scan_run.go`. Every symbol moved; the husk did not.

Separately, `ARCHITECTURE.md:77` describes `scan_config.go` as "scanCmd, 67 flags + init() registration". The real count is **82**.

- [ ] **Step 1: Prove the stub is a stub**

Run: `cat cmd/scan.go` and confirm it contains nothing but `package cmd`. Then run `go build ./cmd/` to confirm the package compiles without it after deletion.

- [ ] **Step 2: Delete it, fix the count, verify**

Delete the file. In `ARCHITECTURE.md`, **remove the number** rather than writing `82` — an exact flag count in prose is a fact that drifts on the next flag added, and this one already drifted silently through 4b and 4c. Describe it as "the flag block + init() registration" instead.

While you are in that line, check it also names the four helpers it lists (`clampWorkers`/`parseSize`/`loadWordlist`/`parseExcludeDir`) accurately against `cmd/scan_config.go`.

- [ ] **Step 3: Verify the CLI surface is unchanged**

Run: `go run . scan --help > /tmp/opencode/4d-help-after.txt 2>&1; wc -l /tmp/opencode/4d-help-after.txt`
Compare against a help capture from the current `HEAD` **before** you delete anything — capture it first, in Step 1. If you cannot produce a genuine pre-change capture, say so rather than diffing a file against itself; `git stash` on a clean tree is a no-op and will silently make the comparison meaningless.

Expected: byte-identical help output.

- [ ] **Step 4: Commit**

```bash
git rm cmd/scan.go
git add ARCHITECTURE.md
git commit -m "refactor(cmd): delete empty scan.go stub; drop stale flag count from docs"
```

---

### Task 5: Hoist the per-call regex compiles in `DetectEncoding`

**Files:**
- Modify: `internal/crawler/encoding.go`

**Interfaces:**
- Consumes: nothing
- Produces: two package-level vars. No exported surface change.

Found during Task 1 and admitted because it is squarely inside this batch's charter: **zero behavior change**. `internal/crawler/encoding.go` compiles two regexes **inside** `DetectEncoding`, on every call:

- `encoding.go:29` — `regexp.MustCompile(`(?i)<meta[^>]+charset=["']?([a-zA-Z0-9_-]+)`)`
- `encoding.go:34` — `regexp.MustCompile(`(?i)<meta[^>]+content=["'][^"']*charset=([a-zA-Z0-9_-]+)`)`

Twenty lines above, at `encoding.go:10`, `charsetRe` is correctly hoisted to a package-level var. So the file already demonstrates the right pattern and then does not follow it. `regexp.MustCompile` on every call is pure repeated work.

- [ ] **Step 1: Hoist both to package-level vars**

Declare them next to `charsetRe`, with names consistent with it (`metaCharsetRe`, `contentCharsetRe` or similar — match the file's existing convention). Delete the inline compiles. **Move the bodies verbatim; change nothing inside them.**

- [ ] **Step 2: Verify identical behavior**

Run: `go build ./... && go test -race ./internal/crawler/ -count=1 && go vet ./internal/crawler/`
Expected: green.

Then confirm behavior is unchanged rather than assuming it: `DetectEncoding` must produce the same result for the same input. The existing crawler tests should cover it — if they do not, say so in your report rather than asserting equivalence you have not checked. If a test is missing for the two meta-charset paths, **add one** (that is characterization, still zero behavior change) and commit it with this task.

- [ ] **Step 3: Commit**

```bash
git add internal/crawler/encoding.go
git commit -m "perf(crawler): hoist per-call regex compiles in DetectEncoding to package level"
```

---

### Task 6: Full gates

**Files:** none — verification only.

- [ ] **Step 1: Fix the stale rule count in the user-facing root help**

Found during Task 4/5's review, and the implementer reported it **backwards** — so read this carefully rather than trusting the queued description.

Batch 2 removed 5 subsumed duplicate rules, reducing 202 → 199. The rule count is now **199**, and `ARCHITECTURE.md` is correct in all four places it appears (lines 34, 91, 278, 453) plus its own changelog entry at line 676. **The stale figure is in `cmd/root.go:13`**, the root command's user-facing help string:

```go
Long: `Syck is a modular secret scanner with 202 detection rules,
```

Verify for yourself before changing anything: `grep -cE "^\s*- name:" internal/rules/builtin.yaml` should be 199, and `grep -rn "202 detection rules\|202 rules" --include=*.go --include=*.md .` should find this line and nothing else that matters.

Fix it to 199. Then check whether `README.md` or any other user-facing surface repeats the wrong number — a stale count in the README is the same bug in a second location.

Capture `syck --help` before and after. **This one legitimately changes output** — it is a correction, not a no-op — so state that explicitly in your report rather than claiming byte-identity the way Task 4 could.

- [ ] **Step 2: Run every gate**

Run: `gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, build OK, vet clean, all tests pass, parity PASS, `40 tested, 40 PASSED`.

- [ ] **Step 3: Confirm the branch is genuinely behavior-neutral**

Run: `git diff --stat <4d-base>..HEAD` and account for every changed file. Any file not anticipated by Tasks 1-4 is a scope violation — investigate before accepting.

Also confirm the four deletions/renames left no orphans: `grep -rn "BodyPool" --include=*.go .` returns nothing, and `go build ./...` is clean.

- [ ] **Step 5: Correct the Batch 3 spec's false 3b claim, and queue the unimplemented half**

Found during Task 1's review. `docs/superpowers/specs/2026-10-05-syck-batch3-performance-design.md` states, as work already done:

> "**3b:** ... `fetchURL` reads through a bounded `io.LimitReader` and returns pooled scratch"

**The `io.LimitReader` half is real. The pooled-scratch half was never implemented.** `fetchURL` still does a plain `io.ReadAll(io.LimitReader(...))` at `internal/crawler/crawler.go:516` with no pooling anywhere. `crawler.BodyPool` was the orphan hook left behind — and Task 1 deleted it, so the code-level trace of the unimplemented half is now gone.

Two things to do:

1. **Correct the spec line** so it describes what Batch 3 actually shipped. Do not rewrite the rest of that dated design record — it is history — but do not leave a false claim of completed work in it either.
2. **Queue the gap** in `ARCHITECTURE.md` §15 alongside the existing deferred defects, so the remaining 3b work is discoverable: per-request scratch buffers in `fetchURL` are still allocated per call and never returned to a pool. Note that implementing it is a memory optimization, not a refactor, so it needs its own batch and its own benchmark.

The `CHANGELOG.md` Batch 3 entry makes no pool claim, so it needs no change — verify that yourself rather than taking this on faith.

- [ ] **Step 6: Verify the docs match the tree**

Run: `ls cmd/*.go internal/sqliteutil/` and check `ARCHITECTURE.md` §3 lists `sqliteutil/` if the new package is a sibling of the ones already listed there. If §3 lists every `internal/` package, omitting the new one would be the same class of omission 4c's review caught for `netguard` and `internalurl`.

Commit only if you changed something:

```bash
git commit -m "docs: list sqliteutil in the architecture package map"
```