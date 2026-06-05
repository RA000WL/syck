# Module 09 — Confidence Scoring

> Composite confidence score: regex +40, entropy +20, context +15, verification +50, credential pair +30. Bands: LOW / MEDIUM / HIGH / CRITICAL.

## Status

- **Tier:** P0
- **Phase:** V1.0
- **Action:** new
- **Owner:** unclaimed
- **New package:** `internal/confidence/`

## Goal

Each finding carries a confidence score independent of its severity. A `CRITICAL` finding (high-impact rule like `aws_secret_access_key`) with weak context (no surrounding keywords, no verification) is still useful, but the consumer can demote or filter it. Confidence and severity are orthogonal: a `MEDIUM` severity finding with `VERY_HIGH` confidence is still very likely to be a real secret.

## Tasks

- [ ] Create `internal/confidence/confidence.go` with the public `Scorer` type and `Score(Signals) int` method.
- [ ] Define `Signals` struct: `RegexMatch bool`, `Entropy float64`, `HasContextKeyword bool`, `Verified bool`, `InCredentialPair bool`, `Length int`, `Alphabet entropy.Alphabet` (from M2).
- [ ] Scoring:
  - `RegexMatch` → +40
  - `Entropy >= 4.5` → +20 (use the alphabet-specific value from M2)
  - `HasContextKeyword` → +15 (context keyword from M1 rule, e.g. "github", "aws")
  - `Verified` → +50 (M4 returns `StateVerified`)
  - `InCredentialPair` → +30 (M5 emitted a correlated finding)
- [ ] Bands:
  - `0-30` → `LOW`
  - `31-60` → `MEDIUM`
  - `61-90` → `HIGH`
  - `91+` → `CRITICAL`
- [ ] `Band(score int) string` and `Confidence` type (LOW/MEDIUM/HIGH/CRITICAL) on `finding.Finding`.
- [ ] Wire the scorer into the scanner pipeline (M11). Every finding that flows through gets a `Confidence` field set.
- [ ] Unit tests: each signal contributes the documented points; band boundaries are inclusive; a finding with all five signals hits `CRITICAL`.

## Exit Criteria

- [ ] `go test ./internal/confidence/...` passes.
- [ ] A finding with all five signals has `Score == 155` and `Band == "CRITICAL"`.
- [ ] A finding with no signals has `Score == 0` and `Band == "LOW"`.
- [ ] Band boundary tests: `Score == 30` → `LOW`, `Score == 31` → `MEDIUM`, `Score == 60` → `MEDIUM`, `Score == 61` → `HIGH`, `Score == 90` → `HIGH`, `Score == 91` → `CRITICAL`.
- [ ] `finding.Finding` has a new `Confidence` field. All formatters render it. Default value is `LOW` for findings produced before the scorer runs.
- [ ] No regression: the V6 benchmark (17 correct, 0 wrong) still produces 17 correct-rule matches.

## Dependencies

- Depends on: M1 (rule provides `context_keywords` and the regex match signal), M2 (alphabet-specific entropy), M4 (verification state), M5 (credential pair signal)
- Depended on by: M11 (scanner pipeline calls the scorer for every finding), M12 (formatters surface confidence)

## Notes for implementer

- Confidence is a **new** field on `finding.Finding`. Severity stays. The two are independent and the formatters (M12) render both.
- The scorer is a pure function: same `Signals` in, same `Score` out. No I/O, no globals, no goroutines. Trivial to test.
- The `Verified` signal is only available after M4 runs. The pipeline stages must run in order: rule → entropy → correlation → verification → confidence. Confidence is the **last** stage, computed once at the end.
- Do not let confidence override severity. A `CRITICAL` severity finding (e.g. AWS secret access key) is still `CRITICAL` severity regardless of confidence. The two communicate different things to the consumer.
- The V1 spec calls the highest band `CRITICAL`; the existing `finding.Severity` enum also has `CRITICAL`. To avoid confusion, the confidence band type should be named `Confidence` (not `Severity`) and live in its own enum.
