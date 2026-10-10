# Session handoff

**Latest: 2026-10-10, tree clean at `521c41e`.** For earlier state see
"Session 1" below; it is kept as history, not as the current position.

## State

Tree clean at `521c41e`, on `main`, **77 commits ahead of `origin/main` and deliberately unpushed** (standing user preference: do not push).

Final gates on `521c41e`: `gofmt -l .` empty · `go build ./...` OK · `go vet ./...` clean · `go test -race ./...` no failures · `TestParityFindingsUnchanged` PASS · `go run . ruletest` 40/40 · `grep -c entropy_threshold internal/rules/builtin.yaml` = 1.

## What landed this session

Batches 9, 10, 11 — run in **parallel** across three git worktrees by three `step-5-preview-free` subagents, then merged sequentially onto main.

| Batch | Change | Result |
|---|---|---|
| 9 | `internal/scanner/multiline.go` gains entropy floor + `RequiresContext` + the three `IsFalsePositive*` filters | 10→9 findings; the one removed is a degenerate repeated-char value. `IsFalsePositiveToken` exempted for multi-line spans so CRITICAL PEM blocks survive. |
| 10 | `jsanalysis` loopback extractor widened (any case, all of 127/8, `::1`, `0.0.0.0`) **and anchored** in one edit | 3 under-matched classes now report; embedded tokens report the whole host instead of a carved substring. |
| 11 | `crawler.fetchURL` buffers its scratch, benchmark-gated | allocs/op 86→77 (−10.5%), B/op 19,595→11,010 (−43.8%). No output change. |

Merge commit `6668eeb`; reconciliation corrections `b46fc6f`.

## Process notes worth keeping

- **Parallel subagents with disjoint touch sets work well when isolated in worktrees.** The only conflicts were in the two shared doc files, and the production diffs came through verbatim (verified byte-identical against each branch tip).
- **The merge reconciliation was the risk, not the merge.** A review of the merged tree found five documentation errors I introduced by hand-editing — including a dropped clause and a miscount. All fixed in `b46fc6f`.
- Batch 11's agent **corrected my own test instruction**: the sequential aliasing test I asked for *cannot* fail with a premature `Put`, because `string(b)` always copies. It proved that, then wrote a concurrent test that does catch it (10/10 failures without `-race`, 5/5 with). Its two own tests also caught two real bugs in its implementation.

## Remaining work

From `ARCHITECTURE.md` §15 as of `b46fc6f`:

- **Item 6** — OPEN **by explicit decision**: `env_generic_secret`'s 3.0 floor judges the whole `KEY=value` span, so the key name supplies most of the entropy and 21/21 common weak secrets pass. Measured and recorded. Do not "fix" by adding a capture group — that silently re-tightens the floor on all five paths.
- **Item 8** — structurally unactionable: `url_secrets.go` takes no `*rules.RuleSet`, so it cannot honor per-rule thresholds.
- Residual link-local asymmetry under item 9: `internalurl` has no category for link-local, so `[fe80::1]` classifies as public. Deliberate; needs a decision, not a fix.
- Residual placeholder shape under item 7: `IsFalsePositiveSecret` is structurally unreachable on the multi-line path (`kvPlaceholderRe` is `^…$`-anchored and its capture cannot cross the newline the structured rules require). Pinned by `TestMultiLineResidualPlaceholderStillReported`.

Recorded decisions not to relitigate: `--git-history` failure stays a stderr warning with exit 0; `env_generic_secret` floor stays as-is; `stage_rule.go` stays unfiltered because `Pipeline` is test-only.

## Session 2 — 2026-10-10

Clean at `36199e3`, 67 commits unpushed.

**Batch 12 landed: credential-pair correlation now runs on the CLI.** Grounding
before the spec found two things worth knowing:

1. **Only 4 of 8 detectors can fire.** `CloudflareDetector`,
   `GitHubAppDetector`, `JWTKeyDetector`, `OAuthDetector` are dead — their
   component rules do not exist in `builtin.yaml`. Recorded, not fixed: adding
   detection rules is its own decision. `DatabaseURLDetector` is live and is
   *not* a pair — it matches each finding's own `Secret` and reports that one
   finding, so `Components` has length 1.
2. **Three latent defects, fixed as part of the same edit.** Correlated findings
   carried the zero `SeverityInfo` (0), which is below the CLI default
   `--severity LOW`; `MinSeverity` is applied *inside* the scan paths, so a
   post-collection append bypassed `--severity` entirely; and `matchPair` stamped
   a `Confidence` of `"VERY_HIGH"`, which `confidence.Band()` can never produce.

All three are now derived: severity is `max(components)`, the band is
`Band(max component score)`, and the hook self-filters by `MinSeverity`.

Review then found two more, both fixed in `36199e3`:
- `database_url_with_credentials` fired **per finding**, so one `.env` line with
  a credential-bearing URL produced three rows with contradictory severities.
  `collapsePairs` merges them and keeps the **max** severity — deliberately not
  `finding.Deduplicate`, which keeps the first row and would silently lower the
  pair below its own worst component. Mutation-verified in both directions.
- A pair row's `Context` was identical to its `Secret`, so `--redact` masked the
  whole row into `*****`. Context now names the two component rule names.

Note the dead-detector count: my spec said 5, the truth is 4, because I counted
`DatabaseURLDetector` as dead when it is live. The docs had it right two sections
away from where I wrote it wrong — the same failure mode as the Batch 8 commit
message.

Parity golden gained exactly one line (`stripe_credential_pair`), because that
fixture already held both Stripe components and the pair was previously
invisible.

## Session 3 — 2026-10-10 (later)

Clean at `521c41e`. **Batches 13–14 landed.**

- **Batch 13** — `--param-brute` appended findings after collection with no
  severity floor, so `--severity CRITICAL` still printed `hidden_parameter`
  rows. This is the invariant Batch 12 closed for credential pairs and left
  open here. The subagent extracted the loop into `appendParamBruteFindings`
  and filters at the append, in `cmd/` rather than `internal/parambrute`
  because `BruteForce` returns `[]ParamFinding` which has no severity field.
- **Batch 14** — `stage_confidence.go` hardcoded `InCredentialPair: false`, the
  signal's only construction site, so `PtsCredPair` (30) never fired. Now
  derived from a `_credential_pair` suffix on the rule name. **Inert on the
  CLI** — the stage is test-only and skips findings that already carry a
  score — so it corrects the dormant path without changing live output.

Review then found four statements in the record that contradicted the code, all
fixed in `521c41e`. The load-bearing one: `detector_jwt_key.go` emitted
`jwt_key_pair`, breaking the suffix convention every doc claimed was universal.
It was masked because the JWT detector is dead, but `ARCHITECTURE.md`
anticipates its rules arriving "with no scan-path edit" — at which point that
pair would silently lose the bonus. Renamed to `jwt_key_credential_pair`, and
the pin widened from 3 to 7 detectors (it covers the dead ones too, because the
detectors match on the rule names they are handed). Re-introducing the old name
now fails with a message naming the type.

Also corrected: a "40 → 70" claim in the CHANGELOG that was wrong on both
numbers, and batch counts that said eleven/seven while adding an
output-changing batch.

**Two Minor items were left and are noted in the review, not fixed:** the
`--param-brute` stderr line counts *unfiltered* results so
`--severity CRITICAL --param-brute` prints "found N interesting parameters"
over a report containing 0 (faithful to pre-existing behaviour, but the floor
introduced the divergence); and `stage_confidence`'s comment cites the
`Confidence != 0` guard as the reason for inertness when the operative reason
is that `NewPipeline` is test-only.

## Suggested next step

The only remaining queued item is the four dead detector rule sets — adding
`cloudflare_*`, `github_app_*`, `jwt`/`jwt_signing_key`, `oauth_*` so those four
pairs start reporting. Adjacent rules exist to build on
(`cloudflare_global_api_key`, `jwt_token`, `github_app_token`,
`google_oauth_token`). This is a **detection-coverage decision**, not a defect
fix: it will report findings nobody sees today, so it needs its own
characterization, its own CHANGELOG entry, and a `ruletest` count change (199 →
199+N). Everything else in §15 is either a deliberate decision or
structurally unactionable. Remaining items are
deliberate decisions, not work:
- item 6 — the `env_generic_secret` floor, OPEN by explicit decision (measured:
  21/21 weak secrets pass, and raising the floor cannot help because the key name
  dominates the span's entropy)
- item 8 — `url_secrets.go` structurally cannot honor per-rule thresholds
- residuals under items 7 and 9 (unreachable `IsFalsePositiveSecret` on the
  multi-line path; no `internalurl` category for link-local)

Batches worth considering, none of them defects:
- add the four missing rule sets so the dead detectors start firing (a
  detection-coverage decision with its own blast radius)
- `PtsCredPair` is unreachable, so a pair scores 40 not 70 — a scoring-design
  question
- `--param-brute` appends findings post-collection with no severity floor, the
  one remaining bypass of the `--severity` invariant Batch 12 closed for
  correlation Its 8 detectors are reachable only from test-only `NewPipeline` — never on the CLI path. This was the largest queued item and the user approved wiring it in. It touches `internal/scanner` broadly, which is why it had to wait for Batch 9 to merge first. Expect a real blast radius on detection output; characterize before changing and CHANGELOG it as an addition.

Do this one in a worktree of its own rather than in parallel — `internal/scanner` is the widest surface in the repo.
