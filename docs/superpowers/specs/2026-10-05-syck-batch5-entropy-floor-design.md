# SYCK Batch 5 — Entropy Floor Consistency — Design Spec

Date: 2026-10-08
Status: approved by grounding; implementation plan to follow

## 1. Intent

Three rule-matching scan paths hardcode the global entropy floor `2.0` instead of honoring each rule's own `entropy_threshold`. One rule in the ruleset sets a threshold (`env_generic_secret`, 3.0), so those three paths are the **only** places that rule is reported below 3.0.

The effect is not "three paths lose detections." It is "the same secret is reported when found via a URL parameter, reconstructed JS, or a JSON value, but not when found in a plain file." That is an inconsistency, and this batch removes it.

## 2. Correction to the Batch 4d queue note

The 4d queue recorded this as:

> `internal/jsrecon`, `internal/json_scanner`, and `internal/scanner/url_secrets.go` have **no per-rule entropy gating** (`url_secrets.go` hardcodes `if e < 2.0`)

**"No per-rule gating" is right; implying no gating at all is wrong.** All three sites *do* gate — on the hardcoded global floor:

| Site | Line | Current gate | Runs the ruleset? |
|---|---|---|---|
| `internal/scanner/url_secrets.go` | 40 | `if e < 2.0` | yes (`rs *rules.RuleSet`) |
| `internal/jsrecon/reconstruct.go` | 411 | `if e < 2.0` | yes (`rule.MatchAll`) |
| `internal/json_scanner/scanner.go` | 103 | `if e < 2.0` | yes (`rs *rules.RuleSet`) |
| `internal/json_scanner/scanner.go` | 71 | `if e >= 3.0` | **no** — key-name heuristic, not a rule match |

The two paths that already do it correctly, generically across every rule:

- `internal/scanner/helpers.go:555` — `if e < decoder.RuleEntropyFloor(rule.EntropyThreshold)`
- `internal/scanner/scan_stream.go:101` — same

Both apply to **all** rules unconditionally. So normal file scanning already enforces the 3.0 floor on `env_generic_secret`.

## 3. What changes

Replace the hardcoded `2.0` at the three ruleset call sites with `decoder.RuleEntropyFloor(rule.EntropyThreshold)`.

**`json_scanner.go:71` does not change.** Its `e >= 3.0` guards the *secret-key-name heuristic* branch (`secretKeyRE.MatchString(keyName)`), which is not a rule match and has no `rule` in scope to read a threshold from. Its floor is a property of that heuristic, not of a rule. Leave it, and say in a comment why it is legitimately different — otherwise a future reader will "unify" it too.

For the other three, the value is unchanged for every rule except `env_generic_secret`, because `RuleEntropyFloor(0) == 2.0`. There is exactly one `entropy_threshold` in `internal/rules/builtin.yaml`.

## 4. Behavior change, stated precisely

For `env_generic_secret` only, a match whose captured value has Shannon entropy in `[2.0, 3.0)` is no longer reported **when it is reached via a URL parameter, reconstructed JavaScript, or a JSON value**.

It remains reported via ordinary file scanning at no different rate than before, because `helpers.go`/`scan_stream.go` already applied the 3.0 floor there.

Concrete examples now suppressed in those three paths: `MY_SECRET=aaaaaaaa`, `DB_PASSWORD=hunter2hunter2` — low-entropy values that the main scanner has always suppressed for this rule.

This must appear in `CHANGELOG.md` under `[Unreleased]`, framed as consistency, with the note that the *same* input was already suppressed on the main file-scanning path.

## 5. Testing

- **Characterize first, per path.** Before changing anything, pin the current behavior of each of the three sites with a test that includes an `env_generic_secret` match at entropy below 3.0 and one above it, so the delta is visible rather than inferred.
- After the change, assert the below-3.0 case is gone from all three and the above-3.0 case survives in all three.
- Add a test asserting `json_scanner.go:71`'s `3.0` heuristic floor is **unaffected**, so a future unification attempt fails visibly.
- Parity harness green throughout. Note the parity fixtures are unlikely to contain `env_generic_secret`; if they do not, the parity harness will NOT catch this change and the per-path characterization tests are the only gate. Say so explicitly rather than leaning on parity.

## 6. Risks

- **Import cycle.** `json_scanner` and `jsrecon` must import `internal/decoder` for the helper. `decoder` must not import either. Verify before committing.
- **The three sites have different surrounding logic.** `url_secrets` scores `PtsRegex + PtsContext` regardless of the rule's threshold; `jsrecon` prefixes the rule name with a tag. Do not unify anything beyond the gate.
- **`requires_context` and `IsFalsePositiveSecret` are separate filters.** `helpers.go` applies both `RuleEntropyFloor` and `entropy.IsFalsePositiveSecret`. The three sites apply neither `IsFalsePositiveSecret` nor `requires_context` in the same way. **This batch fixes only the entropy floor.** Widening it to the other filters is a different change with a different blast radius — record it as a queued follow-up, do not do it here.