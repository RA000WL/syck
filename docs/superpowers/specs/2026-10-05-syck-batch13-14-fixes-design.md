# SYCK Batches 13–14 — Two Small Fixes — Design Spec

Date: 2026-10-10
Status: grounded; two independent defects on disjoint surfaces

## 1. Batch 13 — `--param-brute` bypasses `--severity`

`cmd/scan_run.go:451-469` appends `--param-brute` findings after collection with
**no severity floor**. The severity it assigns can be `finding.SeverityInfo` (0)
when a parameter is neither reflected nor interesting, so:

```
syck scan <url> --severity CRITICAL --param-brute
```

still prints INFO-severity `hidden_parameter` findings. Batch 12 closed exactly
this invariant for credential-pair correlation and left this one open — the same
class of bug, one call site away.

**Fix:** filter the appended findings by the scan's `MinSeverity`, at the point
of append. The filter belongs here rather than inside `parambrute`: the package
produces findings without a severity notion of its own (`BruteForce` returns
`[]ParamFinding` and the caller maps to severity), so the floor is the caller's
concern. State that in a comment so a reader does not move it into the package.

## 2. Batch 14 — `PtsCredPair` is unreachable

`internal/confidence/confidence.go` defines:

```go
InCredentialPair bool     // Signals.InCredentialPair
PtsCredPair = 30
```

and the scorer adds 30 when it is set. But the only construction site,
`internal/scanner/stage_confidence.go:32`, hardcodes it `false`. So a
credential pair — two findings that together form a working credential, the
highest-value correlation shape the tool produces — scores 40 and never 70.

**Fix:** set `InCredentialPair` from the finding itself rather than a constant.
The natural source is `DetectionMethod`, which the correlation wiring already
sets to `"correlation"` (`internal/scanner/correlation_wiring.go`). Check
whether `DetectionMethod == "correlation"` is a precise predicate for "this
finding is a correlated pair" — `database_url_with_credentials` also carries it,
and that one is a single component, so decide deliberately whether it counts.

Note `ConfidenceStage` is on the **test-only** Pipeline, so this wiring may be
inert on the CLI. Establish that before claiming a behavioural change: if
`ConfidenceStage` never runs on the CLI, then the fix is a correctness fix in a
component that will matter the day it is wired, not a live scoring change. Say
which, and do not claim a user-visible delta if there is none.

## 3. Direction

- Batch 13: findings go **down** (INFO hidden-parameter findings stop appearing
  under a floor that should have excluded them). This is a bug fix.
- Batch 14: confidence scores for correlated findings change. Whether any
  user-visible output changes depends on whether the stage runs on the CLI.

## 4. Testing

Characterize before changing, per the standing rule.

Batch 13: a scan with `--severity CRITICAL` and `--param-brute` must show no
INFO/MEDIUM/HIGH hidden-parameter findings. Requires an HTTP fixture — the
existing `fetch_test.go` / crawler tests show the `httptest` style.

Batch 14: a correlated finding's score must include the 30 points when the
signal is set. Assert the number, not "is higher".

## 5. Risks

- Batch 13's filter must not suppress findings that the floor *should* keep —
  `Interesting` maps to HIGH and `Reflected` to MEDIUM, so under
  `--severity HIGH` only interesting parameters survive. Pin that.
- Batch 14: if `DetectionMethod == "correlation"` also catches the
  single-component DB-URL detector, a one-component "pair" would get the pair
  bonus. Decide and record; do not let it happen by accident.
- Do not change `PtsCredPair`'s value or the other point values.
