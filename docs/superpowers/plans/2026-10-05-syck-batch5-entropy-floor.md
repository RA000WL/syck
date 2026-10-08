# SYCK Batch 5 Entropy Floor Consistency — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two outlier rule-matching paths honor each rule's `entropy_threshold`, the way the two main paths already do. **One behavior change, affecting one rule.**

> **Amended after Task 2 (2026-10-06).** This plan originally named **three**
> sites. `internal/scanner/url_secrets.go` turned out **not to run the ruleset
> at all** — `ExtractURLSecrets(line, path, lineno)` takes no `*rules.RuleSet`
> and emits `url_*` names that are not builtin rules, so `rule.EntropyThreshold`
> is not readable there. That site is out of scope. The batch is **two** paths.
> The implementer left it untouched and added a tripwire test
> (`TestURLSecretsRuleNamesAreNotBuiltinRules`) so a future unification attempt
> fails visibly. Do not "fix" `url_secrets.go` to match this plan's older text.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch5-entropy-floor-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Exactly two production edits** (`jsrecon/reconstruct.go`, `json_scanner/scanner.go`), each replacing a hardcoded `2.0` with `decoder.RuleEntropyFloor(rule.EntropyThreshold)`. Nothing else in production code. `url_secrets.go` is **not** one of them — see the amendment above.
- **Three call sites are in scope; change two.** `json_scanner.go:71` keeps its `e >= 3.0` — it guards a key-name heuristic, not a rule match, and has no `rule` in scope. A test must pin that it stays. `url_secrets.go:40` is out of scope entirely (amendment above).
- **Characterize before changing.** Each site gets a test pinning its current behavior with an `env_generic_secret` match below and above 3.0 entropy, so the delta is measured rather than assumed.
- **Parity will probably not catch this.** The parity fixtures are unlikely to contain `env_generic_secret`. Treat the per-path characterization tests as the real gate, and do not cite parity as evidence.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, parity PASS, `go run . ruletest` 40/40.

## Why this is a consistency fix, not a detection regression

State this in the CHANGELOG, because the surface reading is "fewer findings":

`internal/scanner/helpers.go:555` and `internal/scanner/scan_stream.go:101` already apply `decoder.RuleEntropyFloor(rule.EntropyThreshold)` to **every** rule. `env_generic_secret` is the only rule in `internal/rules/builtin.yaml` with a threshold (`3.0`). So today the same `MY_SECRET=aaaaaaaa` is reported when reached via reconstructed JS or a JSON value, and **not** reported when found in a plain file. This batch removes that disagreement.

> **Do not extend this sentence to the URL-parameter path.** `url_secrets.go` emits
> `url_*` names and never an `env_generic_secret` finding, so "the same input is
> reported via a URL parameter" was never true. The two paths Batch 5 changed are
> reconstructed JavaScript and JSON only.

---

### Task 1: Characterize the three sites

**Files:**
- Create: `internal/jsrecon/reconstruct_entropy_test.go`
- Create: `internal/json_scanner/scanner_entropy_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: tests only. No production change in this task.

- [ ] **Step 1: Read the three call sites and their surroundings first**

`internal/jsrecon/reconstruct.go:411`, `internal/json_scanner/scanner.go:103`. Note what `e := entropy.Shannon(...)` is computed over: the **whole match span**, not a captured value. `rules.MatchAll` wraps `FindAllStringIndex` and returns only `[start, end]` — no submatch indices — and `env_generic_secret`'s pattern has **zero** capturing groups, so `secret = text[m[0]:m[1]]` is the entire `MY_SECRET=aaaaaaaa`, never `aaaaaaaa`. This is what makes the 3.0 floor weaker than it reads; see `ARCHITECTURE.md` §15 item 6. Measure the span, not a value you imagine the regex captures.

- [ ] **Step 2: Write the characterization tests**

For each in-scope site, drive it with a ruleset containing `env_generic_secret` and content that produces two matches — one whose **whole match span** is below 3.0 entropy and one above. Assert the **current** behavior: both are reported, because the hardcoded floor is 2.0.

Useful low-entropy and high-entropy value shapes: repeated characters (`aaaaaaaa`) sit well below 3.0; a long mixed alphanumeric string sits above. **Verify the actual entropy** with a throwaway `entropy.Shannon` call rather than assuming — if your "high" example is under 3.0 the test will encode the wrong thing.

Record the exact entropy values you measured in each test's comment, so a future reader can see the margin.

- [ ] **Step 3: Verify and commit against unmodified code**

Run: `go test ./internal/scanner/ ./internal/jsrecon/ ./internal/json_scanner/ -count=1 -v`
Expected: PASS against current behavior. If a case fails, you derived the expectation wrong — fix the expectation, not the code. Nothing in production may change.

```bash
git add internal/jsrecon/reconstruct_entropy_test.go internal/json_scanner/scanner_entropy_test.go
git commit -m "test: characterize the hardcoded 2.0 entropy floor in the three rule-matching paths"
```

---

### Task 2: Honor the per-rule threshold in all three paths

**Files:**
- Modify: `internal/jsrecon/reconstruct.go:411`
- Modify: `internal/json_scanner/scanner.go:103`
- (NOT `internal/scanner/url_secrets.go` — it does not run the ruleset)

**Interfaces:**
- Consumes: `decoder.RuleEntropyFloor(th float64) float64` (already exists in `internal/decoder/pipeline.go:129`)
- Produces: no signature changes

- [ ] **Step 1: Check for an import cycle before editing**

`json_scanner` and `jsrecon` must be able to import `internal/decoder`. Verify `internal/decoder` does not import either. `internal/scanner` already imports `decoder`, so `url_secrets.go` needs no new import.

Run: `go list -deps ./internal/decoder | grep -E "json_scanner|jsrecon"` — expect no output.

- [ ] **Step 2: Make the three edits**

Each is the same shape — replace the literal with the helper, using the `rule` already in scope at that point:

```go
if e < decoder.RuleEntropyFloor(rule.EntropyThreshold) {
    continue
}
```

**`json_scanner.go:103` uses `continue`, not a positive condition** — match the surrounding control flow exactly rather than rewriting it.

At each site, ensure a `rule` with its `EntropyThreshold` is genuinely in scope. In `json_scanner` the ruleset branch and the key-name branch are different blocks; make sure you edit the **ruleset** one (line ~103) and not the heuristic one (~71).

- [ ] **Step 3: Verify the delta is exactly what was characterized**

Run: `go test ./internal/scanner/ ./internal/jsrecon/ ./internal/json_scanner/ -count=1 -v`
Expected: the below-3.0 cases now produce **no** finding; the above-3.0 cases still produce one. Update only those assertions — **if any other case changed, stop and report it.**

- [ ] **Step 4: Commit**

```bash
git add internal/jsrecon/reconstruct.go internal/json_scanner/scanner.go
git commit -m "fix(detection): honor per-rule entropy_threshold in jsrecon and json_scanner rule-match paths"
```

---

### Task 3: Pin the heuristic floor that must NOT move

**Files:**
- Modify: `internal/json_scanner/scanner_entropy_test.go` (from Task 1)

- [ ] **Step 1: Add the guard test**

`internal/json_scanner/scanner.go:71` guards the key-name heuristic with `e >= 3.0`. That branch has no `rule` in scope — it fires on `secretKeyRE.MatchString(keyName)` — so its floor is a property of the heuristic, not of a rule. Write a test that pins its current behavior and add a comment saying it is **deliberately** not `RuleEntropyFloor`, with the reason.

This test exists so that a future "consistency" pass cannot unify it without failing visibly.

- [ ] **Step 2: Commit**

```bash
git add internal/json_scanner/scanner_entropy_test.go
git commit -m "test(json_scanner): pin the key-name heuristic floor as deliberately not per-rule"
```

---

### Task 4: CHANGELOG + queue the adjacent gap

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write the entry under `[Unreleased]`**

Frame it as **consistency**, not loss, and say why:

- `env_generic_secret` (the only rule in the ruleset with an `entropy_threshold`, 3.0) is now honored in the **reconstructed-JavaScript and JSON** paths. Do NOT write "URL-parameter" here: `url_secrets.go` emits `url_*` heuristic names, never `env_generic_secret`, so no URL finding changes (see the amendment at the top of this plan and `CHANGELOG.md`).
- Those paths previously applied a hardcoded global floor of 2.0, so they reported matches with entropy in `[2.0, 3.0)` that ordinary file scanning has always suppressed.
- Net effect: the same input no longer produces a finding on one path and silence on another.
- For every other rule, behavior is unchanged — `RuleEntropyFloor(0)` is 2.0, the value that was hardcoded.

- [ ] **Step 2: Queue the adjacent gap**

The two sites Batch 5 changed also skip `entropy.IsFalsePositiveSecret` and `requires_context`, both of which `helpers.go` applies. (So do `internal/scanner/multiline.go` and `internal/decoder/pipeline.go` — multiline has no entropy floor at all.) That is a **different** change with a wider blast radius — it would suppress more. Record it in `ARCHITECTURE.md` §15 alongside the existing deferred defects, stating the gap precisely and noting it needs its own batch with its own characterization. **Do not implement it here.**

- [ ] **Step 3: Full gates**

Run: `gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, build OK, vet clean, all tests pass, parity PASS, `40 tested, 40 PASSED`.

- [ ] **Step 4: Confirm the blast radius**

Run: `git diff --stat <batch5-base>..HEAD` and account for every file. Production changes must be **exactly three lines** across three files, plus the import additions those need. Anything else is scope creep.

Also confirm: `grep -c "entropy_threshold" internal/rules/builtin.yaml` still returns 1. If this batch somehow changed the ruleset, that is a serious scope violation.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record entropy-floor consistency fix; queue the adjacent filter gap"
```