# Session handoff

**Latest: 2026-10-10, tree clean at `36199e3`.** For earlier state see
"Session 1" below; it is kept as history, not as the current position.

## State

Tree clean at `36199e3`, on `main`, **67 commits ahead of `origin/main` and deliberately unpushed** (standing user preference: do not push).

Final gates on `36199e3`: `gofmt -l .` empty · `go build ./...` OK · `go vet ./...` clean · `go test -race ./...` no failures · `TestParityFindingsUnchanged` PASS · `go run . ruletest` 40/40 · `grep -c entropy_threshold internal/rules/builtin.yaml` = 1.

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

## Suggested next step

Nothing is left in `ARCHITECTURE.md` §15 that is actionable. Remaining items are
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
