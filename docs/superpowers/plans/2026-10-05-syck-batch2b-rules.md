# SYCK Batch 2b Rule FP/FN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut false positives on weak rules, add high-confidence missing token formats, and remove duplicate rules — with every change pinned by corpus + scan-level tests.

**Architecture:** Engine gate first (enforce the parsed-but-dead `Rule.EntropyThreshold`), then YAML-only rule edits in two clusters (prefix tightening, generic-shape gating), then additions + deletions + normalization. Harness (`ruletest`, raw-regex) guards recall; new scan-level tests (gated paths) guard precision, because the harness bypasses `requires_context`.

**Tech Stack:** Go 1.26+, Go regexp (RE2), YAML rule file, existing `ruletest` harness + `internal/scanner` scan paths.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch2-detection-design.md` (section 2b)

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- Context check is same-line, case-insensitive substring (`lineHasContextKeyword`); keywords must be EXTERNAL to the matched token or gating is vacuous.
- `ruletest` stays green for all covered rules (default thresholds: FP 0.5%, FN 5.0%); any recall drop vs pre-change is a bug, never accepted.
- Corpus positives for a tightened rule must meet the NEW minimums (else recall artificially drops).
- No decoder/formatter/dedup/confidence changes (2a done, 2c later).
- Every task ends green: `go build`, `gofmt -l .` empty for touched files, `go vet` on touched packages, targeted `go test -race`.

## Review Focus

- Bare real token without provider keyword (e.g. `ms-`+20 chars on a keyword-less line) no longer fires: expect silence — Task 2 test pins this accepted FN trade-off for 2-char-prefix rules.
- Real tfstate secret without `sensitive` nearby drops CRITICAL→missed and may miss `--fail-on CRITICAL` gates: expect HIGH-only-when-`sensitive`-present — Task 3 test pins the demotion.
- Rewritten OCID pattern must still match real `ocid1.compartment.oc1..aaaa…` IDs: expect match — Task 3 test pins it.
- Deleted-rule coverage must survive: expect every deleted rule's positives to still fire under its keeper — Task 4 subsumption test pins it.
- Rules without `entropy_threshold` must keep the 2.0 floor exactly: expect unchanged behavior — Task 1 zero-threshold test pins it.

---

### Task 1: Enforce per-rule EntropyThreshold in regex paths

**Files:**
- Modify: `internal/scanner/helpers.go` (`scanLineForRegexRulesChunk`, ~540-548: replace hardcoded `2.0` floor with `rule.EntropyThreshold` when `> 0`, else `2.0`)
- Modify: `internal/scanner/scan.go` (streaming regex loop, ~608-610: same replacement)
- Test: `internal/scanner/entropy_threshold_test.go` (create; package `scanner` white-box test calling `scanLineForRegexRulesChunk` directly)

**Interfaces:**
- Consumes: `rules.Rule{EntropyThreshold float64, ...}` (parsed today, never read — verify by grep before editing)
- Produces: same signatures; only the floor value changes per rule. Decoder path (`decoder/pipeline.go`) keeps the 2.0 floor explicitly — out of scope, note in commit body.

- [ ] **Step 1: Write the failing tests**

```go
func TestPerRuleEntropyThresholdEnforced(t *testing.T) {
    // rule with EntropyThreshold 3.0 over a line whose secret has entropy ~2.5: expect 0 findings
    // same rule over a line with entropy >3.5: expect 1 finding
}
func TestZeroThresholdKeepsFloor(t *testing.T) {
    // rule with EntropyThreshold 0 over a ~2.5-entropy match: expect 1 finding (2.0 floor preserved)
}
```

(Build minimal `Config{Rules: &rules.RuleSet{Rules: []Rule{{Name:..., Pattern:..., EntropyThreshold:...}}}}`; compile via `rs.CompileAll()`; craft secrets with known entropy (e.g. repeated-charset vs full-alphabet strings — compute with `entropy.Shannon` in-test to pick values straddling 3.0). Check how existing scanner tests build Config/RuleSet first.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run 'TestPerRuleEntropyThreshold|TestZeroThreshold' -v`
Expected: FAIL (threshold ignored, low-entropy fires)

- [ ] **Step 3: Implement** the floor replacement in both regex paths.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ ./internal/rules/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/helpers.go internal/scanner/scan.go internal/scanner/entropy_threshold_test.go
git commit -m "feat(scanner): enforce per-rule EntropyThreshold in regex paths"
```

---

### Task 2: Short-prefix cluster tightening

**Files:**
- Modify: `internal/rules/builtin.yaml` — exact edits:
  - `elevenlabs_api_key`: pattern `\bsk_[a-zA-Z0-9]{20,}\b` → `\bsk_[a-zA-Z0-9]{32,}\b` (length only, no context gate)
  - `mapbox_api_token`: `\bsk\.[a-zA-Z0-9._\-]{20,200}\b` → `{32,200}` (length only)
  - `moonshot_api_key`: `\bms-[a-zA-Z0-9]{10,}\b` branch → `\bms-[a-zA-Z0-9]{20,}\b` + add `requires_context: true`, `context_keywords: [moonshot, kimi]` (keep `sk-kimi-` branch unchanged)
  - `runway_api_key`: `\brw[-_][a-zA-Z0-9\-_]{10,}\b` → `{20,}` + add `requires_context: true`, `context_keywords: [runway]`
  - `dropbox_api_token`: `\bsl\.[A-Za-z0-9\-_]{10,}\b` → `{16,}` + add `requires_context: true`, `context_keywords: [dropbox, dbx]`
- Modify: `internal/ruletest/generate.go` — add/extend `positiveGenerators` entries meeting NEW minimums: `elevenlabs_api_key` (new, `sk_`+40 alnum), `mapbox_api_token` (new, `sk.`+40 incl `-_.`), `moonshot_api_key` (new, keyword-bearing lines e.g. `MOONSHOT_API_KEY=ms-...20+` and `kimi` variant), `runway_api_key` (new, `RUNWAY_API_KEY=rw-...20+`), `dropbox_api_token` (new, `DROPBOX_TOKEN=sl....16+`)
- Test: `internal/scanner/rule_context_test.go` (create; scan-level gating tests below) + `go run . ruletest --rule <each>`

**Interfaces:**
- Consumes: `lineHasContextKeyword` (whole-line, case-insensitive)
- Produces: YAML-only changes; raw-regex recall preserved for new-minimum positives

- [ ] **Step 1: Write the failing tests** in `internal/scanner/rule_context_test.go` (use `ScanContent` with `rules.LoadDefault()` + `MinSeverity: SeverityLow`, assert per-rule firing):

```go
func TestPrefixClusterGating(t *testing.T) {
    // MOONSHOT_API_KEY=ms-<20+> fires moonshot_api_key; bare "ms-<20+> token" does NOT fire it (accepted FN, pinned)
    // RUNWAY/DROPBOX same shape (keyword fires, bare silent)
    // sk_+40 fires elevenlabs_api_key even bare (length-only, no gate); sk_+24 does NOT fire it
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run TestPrefixClusterGating -v`
Expected: FAIL (old patterns fire on short/bare tokens)

- [ ] **Step 3: Implement** the 5 YAML edits + 5 corpus generators.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ -run TestPrefixClusterGating -v && go run . ruletest --rule elevenlabs_api_key && go run . ruletest --rule mapbox_api_token && go run . ruletest --rule moonshot_api_key && go run . ruletest --rule runway_api_key && go run . ruletest --rule dropbox_api_token`
Expected: PASS, all five `PASSED`

- [ ] **Step 5: Commit**

```bash
git add internal/rules/builtin.yaml internal/ruletest/generate.go internal/scanner/rule_context_test.go
git commit -m "fix(rules): tighten short-prefix cluster (length + context)"
```

---

### Task 3: Generic-shape gating and severity correction

**Files:**
- Modify: `internal/rules/builtin.yaml` — exact edits:
  - `asana_personal_token`: add `requires_context: true`, `context_keywords: [asana]`
  - `basic_auth_header`: add `requires_context: true`, `context_keywords: [authorization]` (external to the `Basic|Bearer` match)
  - `elasticsearch_cloud_id`: add `requires_context: true`, `context_keywords: [elastic, elasticsearch, cloud_id]`
  - `email_address`: add `requires_context: true` (keep existing `context_keywords`)
  - `azure_connection_string`: `AccountKey=[^;]{6,}`-shaped quantifier → minimum `{32,}` (real keys ~88 chars; keep the surrounding pattern identical)
  - `oracle_cloud_ocid`: pattern `\bocid1\.[a-z0-9]+\.[a-z0-9]+\.\.\.\b` → `\bocid1\.[a-z0-9_]+\.[a-z0-9_]+[a-zA-Z0-9._\-]*\b` (drop literal-`...` requirement that only matches redacted docs)
  - `terraform_state_secret`: severity `CRITICAL` → `HIGH`; `context_keywords` → `[sensitive]` (the only discriminator present for truly sensitive values)
  - `kubernetes_kubeconfig_token`: `context_keywords` → `[kubeconfig, users]` (drop vacuous `token`, `user`)
  - `credential_url`: severity `HIGH` → `MEDIUM` (any `user:pass@host` URL is not HIGH by itself)
- Modify: `internal/ruletest/generate.go` — add generators: `asana_personal_token` (`ASANA_TOKEN=1/...` realistic), `oracle_cloud_ocid` (`ocid1.compartment.oc1..` + random), `azure_connection_string` (reuse existing `azure_connection_string` generator if present — check first; else add 88-char-key variant)
- Test: extend `internal/scanner/rule_context_test.go` + `go run . ruletest --rule <each new generator>`

**Interfaces:**
- Consumes: Task 1-2 state (engine gate + test file exist; append new test funcs to `rule_context_test.go`)
- Produces: YAML-only changes (plus generators)

- [ ] **Step 1: Write the failing tests** (append to `rule_context_test.go`):

```go
func TestGenericShapeGating(t *testing.T) {
    // "Bearer <token>" prose: no basic_auth_header; "Authorization: Bearer <same>" fires it
    // bare "user@example.com": no email_address; "Contact support@example.com" fires it
    // "1/abcdef...32hex" bare: no asana_personal_token; "ASANA_TOKEN=<same>" fires it
    // real OCID fires oracle_cloud_ocid; redacted "ocid1.x.y..." short shape behavior pinned as-is
    // tfstate '"value": "ami-123..."' without sensitive: no terraform_state_secret; with "sensitive": true on line: fires HIGH (assert SeverityHigh, not Critical)
    // "token: abc..." bare YAML: no kubernetes_kubeconfig_token; kubeconfig-shaped block fires it
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run TestGenericShapeGating -v`
Expected: FAIL (prose/bare lines fire today)

- [ ] **Step 3: Implement** the 9 YAML edits + generators.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ -run TestGenericShapeGating -v` + `go run . ruletest` full (all covered rules green)
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/rules/builtin.yaml internal/ruletest/generate.go internal/scanner/rule_context_test.go
git commit -m "fix(rules): gate generic shapes, correct severities"
```

---

### Task 4: Additions, deletions, normalization, gates

**Files:**
- Modify: `internal/rules/builtin.yaml`:
  - ADD `openai_legacy_key`: `severity: CRITICAL`, pattern `\bsk-[A-Za-z0-9]{48}\b`, tags `[openai, ai]` (legacy pre-`sk-proj-` format, still in the wild; place directly after `openai_api_key`)
  - ADD `slack_user_token`: `severity: CRITICAL`, pattern `\bxoxp-[0-9A-Za-z\-]{10,200}\b`, tags `[slack, messaging]` (same shape as `slack_bot_token`; place after it)
  - DELETE `discord_webhook` ONLY if its pattern is byte-identical to `discord_webhook_url` (verify in-task; else keep both and note why)
  - DELETE `postgres_connection_url`, `mysql_connection_url`, `mongodb_connection_string` ONLY if each is subsumed (every match also matches `postgres_url`/`mysql_url`/`mongodb_url` — verify with the subsumption test below; else keep and note why)
  - DELETE `gitlab_runner_registration_token` ONLY if its charset is identical to `gitlab_runner_token` (`[0-9a-zA-Z\-_]` vs `[A-Za-z0-9\-_]` — same set; verify + keep `gitlab_runner_token`)
  - Normalize the 9 lowercase `severity:` values (`builtin.yaml:898-953` area: high/medium/critical) to UPPERCASE (Batch 1 made parsing case-insensitive; this aligns source with docs and tooling)
- Explicit non-changes (verified during planning, do not touch): `sendgrid_api_token` pattern already matches the real `SG.<22>.<43>` shape; `shopify_*`, `digitalocean_*`, `jwt_token`/`jwt_in_source`, `redis_*`, `amqp_*` overlaps are distinct shapes covered by cross-rule dedup (2c scope); GitLab `gldt-/glft-` and Slack `xoxa/xoxo/xoxr/xoxs` prefixes are unverified — no rule without a documented format.
- Modify: `internal/ruletest/generate.go` — generators for `openai_legacy_key` (`sk-`+48 alnum), `slack_user_token` (`xoxp-`+50)
- Test: `internal/rules/rule_subsumption_test.go` (create): for each deleted rule, assert its generator positives still match the keeper rule (`keeper.MatchAll(line)` non-empty); assert post-delete `len(builtin rules)` delta equals deletions applied

**Interfaces:**
- Consumes: Tasks 1-3 state
- Produces: final rule count (report new count via `grep -c 'name:' internal/rules/builtin.yaml`)

- [ ] **Step 1: Write the failing tests** — subsumption test (fails: deleted rules still present → count assertion; or if using keeper-only matching, passes trivially — so assert BOTH keeper-matches AND deleted-absent: `rulesByName` has no deleted name). Generator recall covered by harness.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/rules/ -run TestDeletedRuleSubsumption -v`
Expected: FAIL (deleted names still present)

- [ ] **Step 3: Implement** additions + verified deletions + normalization.

- [ ] **Step 4: Run full gates**

Run: `go build -o /tmp/opencode/syck-2b . && gofmt -l . && go vet ./... && go test -race ./...`
Expected: build OK, gofmt empty, vet clean, all PASS

- [ ] **Step 5: Run rule-quality gate**

Run: `go run . ruletest 2>&1 | tail -2 && go run . list-rules 2>&1 | grep -c .`
Expected: all covered rules PASSED (count grows with new generators); list-rules reflects new total

- [ ] **Step 6: Commit**

```bash
git add internal/rules/builtin.yaml internal/ruletest/generate.go internal/rules/rule_subsumption_test.go
git commit -m "feat(rules): legacy/user formats, drop subsumed dupes, normalize severities"
```
