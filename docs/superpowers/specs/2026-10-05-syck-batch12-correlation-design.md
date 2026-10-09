# SYCK Batch 12 — Wire Correlation onto the CLI — Design Spec

Date: 2026-10-09
Status: grounded; 5 of 8 detectors are currently dead

## 1. Intent

`internal/correlation` holds 8 detectors that recognise *credential pairs* — two findings that together form a working credential (an AWS access key id and its secret, within N lines of each other). They are reachable only through `Pipeline`/`CorrelationStage`, which is test-only: `NewPipeline`'s only caller is `pipeline_test.go`. On the CLI they never run at all.

Wire them onto the V6 scan path so the pairs are actually reported.

## 2. Grounded facts

| Detector | Component A | Component B | A severity | B severity | Can fire? |
|---|---|---|---|---|---|
| `AWSDetector` | `aws_access_key_id` | `aws_secret_access_key` | CRITICAL | CRITICAL | yes |
| `StripeDetector` | `stripe_secret_key` | `stripe_publishable_key` | CRITICAL | MEDIUM | yes |
| `TwilioDetector` | `twilio_account_sid` | `twilio_auth_token` | HIGH | CRITICAL | yes |
| `CloudflareDetector` | `cloudflare_email` | `cloudflare_api_key` | — | — | **no** — neither rule exists |
| `GitHubAppDetector` | `github_app_id` | `github_app_private_key` | — | — | **no** — neither rule exists |
| `JWTKeyDetector` | `jwt` | `jwt_signing_key` | — | — | **no** — neither rule exists |
| `OAuthDetector` | `oauth_client_id` | `oauth_client_secret` | — | — | **no** — neither rule exists |
| `DatabaseURLDetector` | — | — | — | — | **own logic**, check `detector_database_url.go` |

So wiring this in produces **three** kinds of finding, not eight. That is the honest state and must be recorded, not papered over. Do **not** add the five missing rule sets in this batch — new detection rules are their own decision with their own blast radius.

## 3. Three defects that must be fixed while wiring it in

Wiring the existing `CorrelationStage.Process` as-is would ship broken output.

**(a) Correlated findings carry no severity.** `finding.Finding`'s zero value is `SeverityInfo` (0). That is a real severity, but the CLI default is `--severity LOW` (1), so a correlated finding at INFO is below the floor.

**(b) Worse, they bypass `--severity` entirely.** `MinSeverity` is applied *inside* the scan paths (`helpers.go:547` and via the sub-scanner calls), not after collection. `CorrelationStage.Process` appends after collection, so a user running `--severity CRITICAL` would still see INFO-severity correlation findings. That is a bug, not a design choice.

**Fix both together:** derive the correlated finding's severity from its components — `max(a.Severity, b.Severity)` — and apply `MinSeverity` to it like any other finding. Deriving is more principled than hardcoding: it stays correct as the component rules' severities are tuned, and it makes `--severity` behave.

**(c) The confidence string is off-band.** `matchPair` sets `Confidence: "VERY_HIGH"` (`internal/correlation/helpers.go:30`), but `confidence.Band()` only ever returns LOW / MEDIUM / HIGH / CRITICAL. `VERY_HIGH` is unreachable from the scorer, so the band field carries a value outside the vocabulary Batch 2c unified.

Fix: derive the band from the components' confidence scores — `confidence.Band(maxScore)` where `maxScore` is the higher of the two components' `Confidence` — rather than passing the literal through. This also removes the sixth `lineHasContextKeyword`-style copy risk by not introducing a new vocabulary.

## 4. Shape

- Hook at the collection boundary of the V6 entry points, so it runs once per scan rather than per file.
- Default **on**, with a `--no-correlation` opt-out, matching how `syck` handles other detection behaviour.
- Findings go **up** — a credential pair is reported in addition to its two components.

## 5. Testing

Characterize first, per path (and the pair fixtures must use documented example credentials):

- an AWS pair within the line span → reported, severity derived CRITICAL, band derived from components
- the same two findings **beyond** the span → not reported
- one component only → not reported
- `--severity CRITICAL` → correlated findings still filtered by it
- `--no-correlation` → none reported

## 6. Risks

- **Do not add the five missing rule sets.** Record them instead.
- **`DatabaseURLDetector` is not a pair** — read it before assuming it fits the shape; it may need different handling from the seven `matchPair` detectors.
- `Secret` on a correlated finding is a *description* string, not a secret. Check what that does to output formats and to the `seen`-map dedup in `recordFingerprints` — a description colliding with a real secret would be a subtle bug.
- The `RuleName` (`aws_credential_pair`) does not exist in the ruleset. Check `--diff`, `IsNew`, and the adaptive/confidence paths do not assume every `RuleName` is a rule.
- `CorrelationStage.Process` also emits into `ConfidenceBand` — that field now feeds the bands users sort by, so an off-band value would be user-visible.
