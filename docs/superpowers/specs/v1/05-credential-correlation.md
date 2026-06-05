# Module 05 — Credential Correlation

> Combine related findings (AWS key + secret, Stripe sk + pk, JWT + signing key) into high-confidence correlated findings.

## Status

- **Tier:** P1
- **Phase:** V1.1
- **Action:** new
- **Owner:** unclaimed
- **New package:** `internal/correlation/`

## Goal

When the scanner finds an AWS access key ID and a matching secret access key in the same file (or within a small line-span window), emit a single correlated finding of type `aws_credential_pair` with confidence `VERY_HIGH` instead of two independent findings. The correlated finding carries both halves and the context that ties them together.

## Tasks

- [ ] Create `internal/correlation/correlation.go` with the public `Correlator` type.
- [ ] Define `CorrelatedFinding` struct: `Type string` (e.g. `aws_credential_pair`), `Confidence confidence.Confidence` (the type defined in M9), `Components []finding.Finding`, `File string`, `Line int`, `Description string`.
- [ ] Add detectors for the V1 spec's correlations:
  - AWS: `aws_access_key_id` + `aws_secret_access_key` within 20 lines
  - Stripe: `stripe_secret_key` + `stripe_publishable_key` within 50 lines
  - Twilio: `twilio_account_sid` + `twilio_auth_token` within 10 lines
  - Cloudflare: `cloudflare_email` + `cloudflare_api_key` within 10 lines
  - GitHub App: `github_app_id` + `github_app_private_key` within 100 lines
  - OAuth: `oauth_client_id` + `oauth_client_secret` within 20 lines
  - Database URL: `postgres://user:pass@host` or `mongodb://user:pass@host`
  - JWT: `jwt` finding + `*_signing_key` finding within 20 lines
- [ ] Each detector is a `Detector` interface with `Match(findings []finding.Finding) []CorrelatedFinding`.
- [ ] Add a `Correlator` orchestrator that runs all detectors and emits correlated findings.
- [ ] Add a `MaxLineSpan` field on each detector (configurable via rule annotation in M1 if time permits).
- [ ] Wire the correlator into the V1 scanner pipeline (M11) as a new stage between rule+entropy and verifier.
- [ ] Unit tests: a fixture file with each correlated pair produces exactly one correlated finding; a file with only one half produces no correlated finding.

## Exit Criteria

- [ ] `go test ./internal/correlation/...` passes.
- [ ] A fixture file containing AWS access key + secret produces one `aws_credential_pair` finding with confidence band `HIGH` or `CRITICAL` (see open question on adding a `VERY_HIGH` band label).
- [ ] A fixture file containing only an AWS access key produces no `aws_credential_pair` finding.
- [ ] All 8 detector types from the V1 spec are implemented and have at least one positive and one negative test case.
- [ ] Correlated findings flow through to the JSON and SARIF formatters as a distinct `type` field.
- [ ] No regression: the V6 benchmark (17 correct, 0 wrong) still produces 17 correct-rule matches with correlated findings emitted in addition.

## Dependencies

- Depends on: M1 (rule names drive correlation rules), M3 (decoded findings feed the correlator), M9 (correlated findings get the +30 confidence bonus)
- Depended on by: M11 (scanner pipeline includes the Correlation Engine stage), M12 (formatters render the correlated type)

## Notes for implementer

- The correlator runs **after** dedup but **before** verification. This way verification can take a correlated finding and verify both halves in one round trip.
- The `Database URL` detector is a special case: it does not match two distinct findings but a single finding whose secret is a URL with embedded credentials. Use a regex like `(?i)(postgres|postgresql|mysql|mongodb|redis|amqp)(\+\w+)?://[^:]+:[^@]+@`.
- Keep the package small. The orchestrator + 8 detectors + types + tests should fit in under 600 lines.
- The `VERY_HIGH` label mentioned in some V1 spec text is not currently a band in M9's enum (LOW/MEDIUM/HIGH/CRITICAL). Either add a `VERY_HIGH` band above `CRITICAL` in M9, or use `CRITICAL` for correlated findings. This is an open question for the M5/M9 implementers.
