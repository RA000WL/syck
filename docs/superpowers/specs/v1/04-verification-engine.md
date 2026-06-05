# Module 04 — Verification Engine

> Confirm found secrets are live against provider APIs. Explicit POTENTIAL/LIKELY/VERIFIED states.

## Status

- **Tier:** P1
- **Phase:** V1.3
- **Action:** refactor
- **Owner:** unclaimed
- **Source package:** `internal/validator/`

## Goal

Refactor the existing validator (registry + 13 providers) to expose explicit `POTENTIAL/LIKELY/VERIFIED` states and add the V1 spec's required endpoints. Preserve the `--validate` flag's best-effort behavior. Add a new `--verify` flag for the V1 state path.

## Tasks

- [ ] Introduce a `State` enum: `StatePotential`, `StateLikely`, `StateVerified`. Add `State` field to `ValidationResult`.
- [ ] Refactor `providers.go` (currently 349 lines) into one file per provider, each implementing a `Provider` interface with `Name()`, `Verify(secret) State`, `Detail()`.
- [ ] Add the V1 spec's explicit endpoint coverage:
  - AWS: `sts:GetCallerIdentity`
  - GitHub: `GET /user`
  - Stripe: `GET /v1/account`
  - OpenAI: `GET /v1/models`
- [ ] Add a rate limiter (token bucket per host) and a thread-safe request pool. Use `golang.org/x/time/rate`.
- [ ] Add `Registry` type with `Register` and `Lookup` methods; replace the package-level `registry` map.
- [ ] Add `--verify` CLI flag in `cmd/scan.go`. When set, validation runs the V1 state path. `--validate` keeps current behavior.
- [ ] Verification is opt-in only. Document this in `--help` output and the README.
- [ ] Unit tests: each new provider returns the expected state for known-good and known-bad tokens (use recorded HTTP fixtures via `httptest`).

## Exit Criteria

- [ ] `go test ./internal/validator/... -race` passes.
- [ ] `--validate` produces the same exit code and the same set of confirmed/unconfirmed findings for the benchmark corpus as the current binary.
- [ ] `--verify` produces a finding stream with `verification.status` populated as one of `POTENTIAL`, `LIKELY`, `VERIFIED`.
- [ ] AWS provider uses `sts:GetCallerIdentity` (not the legacy IAM user lookup).
- [ ] GitHub provider uses `GET /user` and parses `login` for the detail field.
- [ ] Stripe provider uses `GET /v1/account` and parses `display_name` and `country`.
- [ ] OpenAI provider uses `GET /v1/models` and parses the model list length for the detail field.
- [ ] Rate limit is respected: hammering the validator does not produce more than the configured RPS per host.
- [ ] No change to `internal/scanner/scanner.go` callsite shape (it calls `validator.Validate`).

## Dependencies

- Depends on: M1 (rule's `verify` field gates which providers run), M11 (pipeline has a Verifier stage that calls the registry)
- Depended on by: M9 (confidence adds 50 points for `StateVerified`), M12 (reporting surfaces verification status)

## Notes for implementer

- `internal/validator/validator.go` (45 lines) becomes the registry entry point. Each provider moves to `internal/validator/providers/<name>.go`.
- Preserve `ValidationResult.Valid bool` for backward compatibility. Compute it from `State == StateVerified`.
- Use `net/http` for all requests. No new top-level dependency beyond `golang.org/x/time/rate` (which is in the stdlib-adjacent tree and commonly vendored — confirm with the user before adding it to `go.mod`).
- Recorded fixtures: use `httptest.NewServer` and let the test record responses to `testdata/<provider>/<case>.json` on first run. Do not hit real provider APIs in tests.
- Document the "explicit authorization required" warning in `cmd/scan.go` help text and the README.
