# SYCK Batch 7 — Dedup-Key Truncation — Design Spec

Date: 2026-10-08
Status: grounded; 9 sites, one pattern

## 1. The defect

Nine dedup skip-sets truncate their key before comparing:

| Site | Key built from | Truncation |
|---|---|---|
| `gitscan/scanner.go:62` | `RuleName + ":" + Secret` | 80 |
| `scan_stream.go:198,207` | `Secret` | 60 (×2) |
| `scan_file.go:91,109` | `Secret` | 60 (×2) |
| `helpers.go:542,624,719` | `Secret` / token | 60 (×3) |
| `scan_content.go:170` | `Secret` | 60 |

Two distinct secrets sharing a 60-char prefix (43 after a 16-char rule name at the gitscan site) collapse into one finding. Silent false negative.

## 2. Why dropping the truncation only ever adds findings

Every site compares two passes over related content (gzip vs raw, line vs decoded, commit vs commit) to suppress duplicates of the **same** secret. Truncation merges things full keys distinguish; it never splits things full keys merge. Removing it un-merges distinct secrets (correct) and keeps identical secrets merged (unchanged). Direction: findings go up, never down.

Memory: map keys become full secrets instead of 60/80-char prefixes. These are per-file/per-commit skip-sets, freed after use. Some paths already cap `Secret` at 500; unbounded ones are bounded in practice by match length. Negligible.

## 3. What changes

Delete all 9 `if len(key) > N { key = key[:N] }` blocks. Use the full key. Nothing else.

## 4. Testing

Characterize first: construct a colliding pair (two distinct secrets sharing a 60+ char prefix, e.g. two long `firebase_fcm_key`-shaped values diverging late) and assert the current code reports **one**. After the fix, assert **two**. Cover both key shapes: Secret-only (e.g. via gzip double-scan) and RuleName+Secret (gitscan across two commits).

Also assert the still-merged case: the identical secret in both passes reports once.

## 5. Risks

- **None structural.** No signature changes, no new imports, no shared helper needed — the fix is deletion.
- `CHANGELOG.md` must record that previously-merged distinct findings now appear separately.
- Parity harness will not catch this unless fixtures contain colliding pairs — do not cite it.