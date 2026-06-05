# syck-go V1 Roadmap

> Production-grade secret scanner. Bug bounty recon, JavaScript bundle analysis, source maps, CI/CD secrets, cloud credentials, AI provider keys, OAuth leaks, and frontend exposures.

This is the contributor-facing roadmap for the V1 spec of `syck-go`. V1 subsumes the V7 spec and replaces the V7 label throughout the project. The current binary ships with most of the V1 surface already wired; the roadmap covers what is missing, what needs extension, and what needs refactor to land the spec cleanly.

## Status

| Phase | Theme | Status |
|-------|-------|--------|
| V1.0  | Foundation: rule schema, entropy helpers, confidence scoring, scanner pipeline | Complete |
| V1.1  | Decoding & credential correlation | Not started |
| V1.2  | JS / source maps / frontend recon | Not started |
| V1.3  | Verification, rule quality, reporting polish | Not started |

> Move a task from `[ ]` to `[WIP]` in your PR to claim it. Mark it `[x]` when the module's exit criteria are met.

## Module Index

| # | Module | Tier | Phase | Action | Spec |
|---|--------|------|-------|--------|------|
| 1  | Rule Engine            | P0 | V1.0 | extend   | [01-rule-engine.md](docs/superpowers/specs/v1/01-rule-engine.md) |
| 2  | Entropy Engine         | P0 | V1.0 | extend   | [02-entropy-engine.md](docs/superpowers/specs/v1/02-entropy-engine.md) |
| 3  | Decoder Engine         | P0 | V1.1 | extend   | [03-decoder-engine.md](docs/superpowers/specs/v1/03-decoder-engine.md) |
| 4  | Verification Engine    | P1 | V1.3 | refactor | [04-verification-engine.md](docs/superpowers/specs/v1/04-verification-engine.md) |
| 5  | Credential Correlation | P1 | V1.1 | new      | [05-credential-correlation.md](docs/superpowers/specs/v1/05-credential-correlation.md) |
| 6  | JS Analyzer            | P1 | V1.2 | extend   | [06-js-analyzer.md](docs/superpowers/specs/v1/06-js-analyzer.md) |
| 7  | Source Map Analyzer    | P2 | V1.2 | new      | [07-sourcemap-analyzer.md](docs/superpowers/specs/v1/07-sourcemap-analyzer.md) |
| 8  | Frontend Recon         | P1 | V1.2 | new      | [08-frontend-recon.md](docs/superpowers/specs/v1/08-frontend-recon.md) |
| 9  | Confidence Scoring     | P0 | V1.0 | new      | [09-confidence-scoring.md](docs/superpowers/specs/v1/09-confidence-scoring.md) |
| 10 | Rule Quality Testing   | P1 | V1.3 | new      | [10-rule-quality-testing.md](docs/superpowers/specs/v1/10-rule-quality-testing.md) |
| 11 | Scanner Architecture   | P0 | V1.0 | refactor | [11-scanner-architecture.md](docs/superpowers/specs/v1/11-scanner-architecture.md) |
| 12 | Reporting              | P0 | V1.3 | extend   | [12-reporting.md](docs/superpowers/specs/v1/12-reporting.md) |

**Tier legend:** P0 = required for V1 release. P1 = high value, ships if a contributor picks it up. P2 = nice to have, lands when bandwidth allows.

**Action legend:** `extend` = add V1 features to a working package. `refactor` = rewrite internals to match V1 spec, preserve public surface. `new` = net-new package.

## Phase Checklists

### V1.0 — Foundation

Schema, signals, and the new pipeline. Pure CPU work. No HTTP, no new external dependencies.

> Pipeline order: Collector → Decoder → Rule Engine → Entropy Engine → Correlation Engine → Verifier → Confidence → Reporter.

- [x] **M1 Rule Engine (extend)** — extend `Rule` struct with `entropy_threshold`, `context_keywords`, `requires_context`, `verify`, `version`. Add `RuleLoader`, `RuleValidator`, `RuleCompiler` with a regex compile cache and duplicate-rule detection. Rule schema is backward-compatible YAML.
- [x] **M2 Entropy Engine (extend)** — add `Base64Entropy`, `HexEntropy`, `JwtEntropy` helpers. Wire them into the existing entropy token scan so the right variant is selected based on token alphabet.
- [x] **M9 Confidence Scoring (new)** — new `internal/confidence` package. Composite scorer: regex match +40, entropy +20, context keyword +15, verification +50, credential pair +30. Bands: 0-30 LOW, 31-60 MEDIUM, 61-90 HIGH, 91+ CRITICAL. Confidence lives **alongside** severity on every `Finding` (both fields are independent).
- [x] **M11 Scanner Architecture (refactor)** — break `internal/scanner/scanner.go` (currently 631 lines) into the V1 pipeline stages: Collector → Decoder → Rule Engine → Entropy Engine → Correlation Engine → Verifier → Reporter. Public `Config` struct and CLI flag surface preserved.
- [x] **M9 → M11 wiring** — confidence emitted by every stage flows through the pipeline and lands on the final `Finding`.

### V1.1 — Decoding & Correlation

Find secrets hidden inside other formats and combine related findings.

- [ ] **M3 Decoder Engine (extend)** — cap `MaxRecursionDepth` at 3 per spec (currently 4). Add JWT payload split decoder. Add hook for `atob()` and `Buffer.from()` calls in JS-reconstructed strings. Decoder registry becomes thread-safe.
- [ ] **M5 Credential Correlation (new)** — new `internal/correlation` package. Detectors for: AWS access key + secret, Stripe sk + pk, Twilio account SID + auth token, Cloudflare email + API key, GitHub App id + private key, OAuth client id + client secret, database URLs with embedded credentials, JWT + signing key. Emits correlated findings with type `aws_credential_pair` and confidence `VERY_HIGH`.
- [ ] **M3 → M5 wiring** — decoder produces tokens → correlation engine groups tokens that appear close in the same file/line span.

### V1.2 — JS / Source Maps / Frontend Recon

Attack surface on the frontend: bundles, sourcemaps, and exposed admin/dev endpoints.

- [ ] **M6 JS Analyzer (extend)** — extend `internal/jsrecon/reconstruct.go` to extract structured records: `endpoint`, `method`, `headers` (with `Authorization` parsed), `domains`, `api_keys`. Detect `fetch()`, `axios()`, `XMLHttpRequest`, Apollo, GraphQL patterns.
- [ ] **M7 Source Map Analyzer (new)** — new `internal/sourcemap` package. Support `.js.map`, `.map.gz`, and inline `//# sourceMappingURL=...` maps. Workflow: download → reconstruct source → scan reconstructed source → link findings to the original `.js` file. Extract `.env` references, comments, TODOs, dead code, and debug endpoints.
- [ ] **M8 Frontend Recon (new)** — new `internal/recon` package. Detect frontend surface endpoints by category: `graphql`, `swagger`, `openapi`, `admin`, `debug`, `metrics`, `internal`, `staging`, `uat`. Detect cloud storage URLs: `s3.amazonaws.com`, `blob.core.windows.net`, `storage.googleapis.com`. Emits findings of type `attack_surface`.
- [ ] **M6 → M7 wiring** — JS analyzer output feeds the source map analyzer; recon findings surface as `LOW`/`MEDIUM` severity `attack_surface` findings, not secret findings.

### V1.3 — Verification & Quality

Confirm findings, prove the rules are good, polish reporting.

- [ ] **M4 Verification Engine (refactor)** — refactor `internal/validator/providers.go` (currently 349 lines) to explicit `POTENTIAL/LIKELY/VERIFIED` states. Add the spec's explicit endpoints: AWS `sts:GetCallerIdentity`, GitHub `GET /user`, Stripe `GET /v1/account`, OpenAI `GET /v1/models`. Verification is rate-limited, thread-safe, and opt-in only. New `--verify` CLI flag is added; existing `--validate` keeps its best-effort behavior across all 13 providers.
- [ ] **M10 Rule Quality Testing (new)** — new `internal/ruletest` package. Positive corpus harness: 10,000+ real token examples. Negative corpus harness: 100k JS, 100k JSON, 100k HTML files. Tracks precision, recall, false-positive rate, coverage. Rejects any rule whose FP rate exceeds 0.5% on the negative corpus.
- [ ] **M12 Reporting (extend)** — extend JSON, SARIF, and HTML formatters with `confidence`, `verification.status`, and `decoded_value_preview` fields. SARIF output includes `properties` for confidence and verification.

## V1 Acceptance Criteria

V1 is not complete until every box is checked:

```yaml
rule_engine: complete
entropy_engine: complete
decoder_engine: complete
verification_engine: complete
credential_correlation: complete
js_analyzer: complete
sourcemap_analyzer: complete
frontend_recon: complete
confidence_scoring: complete
sarif_reporting: complete
rule_testing_framework: complete
```

## Contribution Guide

1. **Pick a task.** Browse the phase checklists above. Each unchecked item maps to a section in the linked per-module spec.
2. **Claim it.** In your PR, change `[ ]` to `[WIP]` next to the task you are working on. Do not claim more than one task at a time per PR.
3. **Read the per-module spec.** Every module has a stub spec at `docs/superpowers/specs/v1/NN-<module>.md`. The spec lists the tasks in scope, the exit criteria, and (when filled in) the full interface design.
4. **Write tests first.** Every new package must have unit tests in the same package. Every rule change must include a positive and negative fixture.
5. **Update the checklist when done.** Move your task from `[WIP]` to `[x]` and add a one-line note linking to the PR. The exit-criteria checkbox in the per-module spec is the source of truth for module completion.
6. **No drive-by refactors.** Stay in scope. If you discover a related problem, file an issue; do not bundle unrelated changes.

### Conventions

- **Package layout:** new modules go under `internal/<module>/` with one package, one test file, one fixture directory.
- **Naming:** package names are lowercase, single word (`confidence`, `correlation`, `sourcemap`, `recon`, `ruletest`).
- **Public surface:** preserve the existing `scanner.Config` and CLI flag surface unless a per-module spec explicitly says it changes.
- **YAML rules:** add new rules to `internal/rules/builtin.yaml`. Use the extended schema from M1 (all new fields are optional).
- **Dependencies:** avoid new top-level dependencies. Use the Go standard library or existing `go.mod` entries wherever possible.
- **Comments:** code-level comments are discouraged unless the code is non-obvious. Spec docs are the right place for design rationale.

### Testing

- Unit tests live next to the code they cover: `foo.go` → `foo_test.go` in the same package.
- Fixtures live in `internal/<package>/testdata/`. Use `t.TempDir()` for any temporary scratch space.
- Benchmark regression coverage for the pipeline is tracked by the V1.0 exit criteria for M11.

## V6 → V1 Migration Notes

The current binary is what users ship today. V1 is the spec; the path from V6 to V1 is intentionally additive so the binary keeps working at every step:

| V6 surface | V1 surface | Migration |
|------------|-----------|-----------|
| Rule struct (5 fields) | Rule struct (+5 fields, all optional) | Load V6 YAML, new fields default to zero values |
| Validator: `Valid bool` | Validator: `POTENTIAL/LIKELY/VERIFIED` states | `--validate` keeps V6 behavior; new `--verify` exposes V1 states |
| Severity field on Finding | Severity + Confidence (two fields) | All formatters extended; existing severity consumers unchanged |
| `scanner.go` (631 lines) | Pipeline stages across multiple files | Public `Config` and CLI surface preserved |
| 130 built-in rules | 130+ rules, schema-extended | Existing rules work as-is; new rules opt into extended fields |

## Open Questions for V1.0+

These are deliberately not answered in the stub specs. File an issue or claim a task to resolve them.

- Should rule quality testing reject a rule at FP-rate 0.5% during CI, or only emit a warning?
- Should confidence banding override severity in SARIF `security-severity` mapping, or be a separate SARIF property?
- Should source map fetching be opt-in via flag, or always on for `.js` files?
- Should the `--verify` flag require explicit acceptance of an "I have permission to validate against these endpoints" prompt, or just a flag?
