# SYCK Batch 9 — multiline.go Filters — Design Spec

Date: 2026-10-08
Status: grounded; single file, default-on live path

## 1. Intent

`internal/scanner/multiline.go` is the last rule-matching path with no filters at all. It:

- applies **no entropy floor** (no `entropy.Shannon` call in the file)
- applies **no `IsFalsePositive*` filters**
- applies **no `RequiresContext`**

and it runs on a **default-on** path: `--multiline` defaults to true (`cmd/scan_config.go:176`) and `internal/lsp/server.go:180` forces it on. Every span matched by every `multi_line` rule is reported unconditionally.

Batch 8 covered the three paths that already had floors. This one needs floor + filters, a different change shape — hence its own batch.

## 2. Grounding (measured, not assumed)

The 9 `multi_line: true` rules and their configuration:

| Rule | entropy_threshold | requires_context |
|---|---|---|
| `kubernetes_secret`, `docker_compose_secret` | — | — |
| `rsa_private_key`, `dsa_private_key`, `ec_private_key`, `openssh_private_key`, `rsa_public_key`, `pgp_public_key` | — | — |
| `pgp_private_key` | — | — |

**None sets a threshold, none requires context.** Consequences:

- The entropy floor added here is the global `RuleEntropyFloor(0)` = **2.0**, not a per-rule value. Whether a PEM or kubeconfig span clears 2.0 is a measurement, not an assumption — it probably does (base64 is high-entropy), but the batch must show it rather than assert it.
- Adding `RequiresContext` is a **no-op for the current ruleset** and correct for any future `multi_line` rule that sets it. Say so in the code comment, so a reader does not expect it to suppress anything today.

## 3. What changes

Add to `internal/scanner/multiline.go`, mirroring `helpers.go:529-564` order:

1. `RequiresContext` + `lineHasContextKeyword` (the context text is the multi-line window `content`, the text rules are matched against)
2. `entropy.Shannon(secret)` < `decoder.RuleEntropyFloor(rule.EntropyThreshold)` → skip
3. `IsFalsePositiveSecret`, `IsFalsePositiveToken`, `IsFalsePositiveEmail`

**`IsFalsePositiveToken` must be exempted for multi-line spans, exactly as Batch 8 did on the decoded path.** A PEM block is nothing but hyphens and base64; Token's hyphen heuristic (`>= 3` hyphens, `len > 20`) would suppress it. That is the same defect Batch 8 fixed on the decoder path and it must not be re-introduced here. The exemption is the single most important part of this batch.

## 4. Direction

Strictly suppression, except the Token exemption which preserves existing CRITICAL findings. Net: findings go down or stay equal.

## 5. Testing

Characterize first. Drive `ScanMultiLine` with:
- a full PEM block — must still be reported (this is the guard that Batch 8's decoder carve-out exists for)
- a kubeconfig token and a docker-compose secret — likely survivors, must be shown to survive
- a shape that the FP filters should reject — needs constructing, since the multi_line rules match structured content. A hyphen-dense or placeholder-shaped multi-line span.

Assert current behavior (unconditional reporting) first, then the filters' effect.

## 6. Risks

- **Re-introducing Batch 8's PEM suppression.** The Token exemption prevents it; the PEM test proves it.
- `multiline.go` is also used by `lsp` — a forced-on path — so any suppression is visible in the editor, not just the CLI.
- `ScanMultiLine`'s window construction (`startLine`, joined lines) means "the line" for context purposes is the whole window. Document that.
- Parity will probably not catch this — the golden fixtures are unlikely to contain `multi_line` rules. Do not cite it.
