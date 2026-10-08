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
| `internal/jsrecon/reconstruct.go` | 411 | `if e < 2.0` | yes (`rule.MatchAll`) |
| `internal/json_scanner/scanner.go` | 103 | `if e < 2.0` | yes (`rs *rules.RuleSet`) |
| `internal/json_scanner/scanner.go` | 71 | `if e >= 3.0` | **no** — key-name heuristic, not a rule match |
| ~~`internal/scanner/url_secrets.go`~~ | ~~40~~ | ~~`if e < 2.0`~~ | **no — see correction below** |

> **Correction (2026-10-06, during Task 2).** An earlier draft of this table
> listed `url_secrets.go` as running the ruleset. **It does not.**
> `ExtractURLSecrets(line, path, lineno)` takes no `*rules.RuleSet`; it matches
> with a local `urlRE` and emits `url_*` rule names that **are not builtin
> rules** (`grep -c "name: url_" internal/rules/builtin.yaml` → 0). There is no
> `rule` in scope, so `rule.EntropyThreshold` cannot be read. Plumbing a
> ruleset in would require an exported-signature change and would be
> observably a no-op, since no `url_*` rule defines a threshold.
>
> **This batch therefore changes two paths, not three.** `url_secrets.go` keeps
> its `2.0` floor, with a tripwire test asserting its `url_*` names are not
> builtin rules — so a future attempt to unify it fails visibly rather than
> silently misreading a heuristic as a rule match.

The two paths that already do it correctly, generically across every rule:

- `internal/scanner/helpers.go:555` — `if e < decoder.RuleEntropyFloor(rule.EntropyThreshold)`
- `internal/scanner/scan_stream.go:101` — same

Both apply to **all** rules unconditionally. So normal file scanning already enforces the 3.0 floor on `env_generic_secret`.

## 3. What changes

Replace the hardcoded `2.0` at the three ruleset call sites with `decoder.RuleEntropyFloor(rule.EntropyThreshold)`.

**`json_scanner.go:71` does not change.** Its `e >= 3.0` guards the *secret-key-name heuristic* branch (`secretKeyRE.MatchString(keyName)`), which is not a rule match and has no `rule` in scope to read a threshold from. Its floor is a property of that heuristic, not of a rule. Leave it, and say in a comment why it is legitimately different — otherwise a future reader will "unify" it too.

For the other three, the value is unchanged for every rule except `env_generic_secret`, because `RuleEntropyFloor(0) == 2.0`. There is exactly one `entropy_threshold` in `internal/rules/builtin.yaml`.

## 4. Behavior change, stated precisely

For `env_generic_secret` only, a match whose **whole `KEY=value` span** has Shannon entropy in `[2.0, 3.0)` is no longer reported **when it is reached via reconstructed JavaScript or a JSON value**. It is not a captured value: `MatchAll` returns no submatch indices and the rule has zero capturing groups, so the threshold sees the whole span — see `ARCHITECTURE.md` §15 item 6.

The URL-parameter path is **not** affected: `ExtractURLSecrets` emits `url_*` heuristic names and can never produce an `env_generic_secret` finding (it takes no `*rules.RuleSet` — see §5 and the amendment note below).

It remains reported via ordinary file scanning at no different rate than before, because `helpers.go`/`scan_stream.go` already applied the 3.0 floor there.

Measured examples, now suppressed on those two paths:

| Input | Span entropy | Outcome |
|---|---|---|
| `MY_SECRET=aaaaaaaa` | 2.7250 | suppressed (was reported) |
| `DB_PASSWORD=hunter2hunter` | 4.0040 | **still reported** — an earlier draft of this spec wrongly cited this as a suppressed example |

> **Correction (2026-10-06, during Task 2).** An earlier draft cited
> `DB_PASSWORD=hunter2hunter2` as suppressed. It measures **4.0080**, above the
> 3.0 floor, and is still reported. The example was wrong.

### The 3.0 floor is weaker than it looks

> **Finding (2026-10-06, Task 2).** `env_generic_secret`'s pattern has **zero
> capturing groups**, and `MatchAll` wraps `FindAllStringIndex` — so the span
> the threshold is applied to is the **whole `KEY=value` string**, not the value.
> The key name supplies most of the entropy:
>
> | String | Shannon |
> |---|---|
> | `MY_SECRET=aaaaaaaa` (whole span) | 2.7250 |
> | `aaaaaaaa` (value alone) | 0.0000 |
>
> So a completely uniform 8-character secret scores **2.7250**, not 0. The 3.0
> floor does not mean "reject low-entropy secrets" — it means "reject spans that
> are low-entropy *including their key name*." Whether that is the intent is a
> detection-quality question this batch does **not** answer. Queued separately.

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