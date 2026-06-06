# syck-go V1 Roadmap

> Production-grade secret scanner. Bug bounty recon, JavaScript bundle analysis, source maps, CI/CD secrets, cloud credentials, AI provider keys, OAuth leaks, and frontend exposures.

This is the contributor-facing roadmap for the V1 spec of `syck-go`. V1 subsumes the V7 spec and replaces the V7 label throughout the project. The current binary ships with most of the V1 surface already wired; the roadmap covers what is missing, what needs extension, and what needs refactor to land the spec cleanly.

## Status

| Phase | Theme | Status |
|-------|-------|--------|
| V1.0  | Foundation: rule schema, entropy helpers, confidence scoring, scanner pipeline | Complete |
| V1.1  | Decoding & credential correlation | Complete |
| V1.2  | JS / source maps / frontend recon | Complete |
| V1.3  | Verification, rule quality, reporting polish | Complete |
| V1.4  | Rule quality testing harness | Complete |
| V1.5  | FP reduction (media token filter) & performance (line length gate) | Complete |
| V1.6  | Public release: README, release pipeline, version subcommand | Complete |
| V1.7  | Operational polish: env config, TUI progress, SARIF upload | Complete |

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
| 10 | Rule Quality Testing   | P1 | V1.4 | new      | [10-rule-quality-testing.md](docs/superpowers/specs/v1/10-rule-quality-testing.md) |
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

- [x] **M3 Decoder Engine (extend)** — cap `MaxRecursionDepth` at 3 per spec (currently 4). Add JWT payload split decoder. Add hook for `atob()` and `Buffer.from()` calls in JS-reconstructed strings. Decoder registry becomes thread-safe.
- [x] **M5 Credential Correlation (new)** — new `internal/correlation` package. Detectors for: AWS access key + secret, Stripe sk + pk, Twilio account SID + auth token, Cloudflare email + API key, GitHub App id + private key, OAuth client id + client secret, database URLs with embedded credentials, JWT + signing key. Emits correlated findings with type `aws_credential_pair` and confidence `VERY_HIGH`.
- [x] **M3 → M5 wiring** — decoder produces tokens → correlation engine groups tokens that appear close in the same file/line span.

### V1.2 — JS / Source Maps / Frontend Recon

Attack surface on the frontend: bundles, sourcemaps, and exposed admin/dev endpoints.

- [x] **M6 JS Analyzer (extend)** — extend `internal/jsrecon/reconstruct.go` to extract structured records: `endpoint`, `method`, `headers` (with `Authorization` parsed), `domains`, `api_keys`. Detect `fetch()`, `axios()`, `XMLHttpRequest`, Apollo, GraphQL patterns.
- [x] **M7 Source Map Analyzer (new)** — new `internal/sourcemap` package. Support `.js.map`, `.map.gz`, and inline `//# sourceMappingURL=...` maps. Workflow: download → reconstruct source → scan reconstructed source → link findings to the original `.js` file. Extract `.env` references, comments, TODOs, dead code, and debug endpoints.
- [x] **M8 Frontend Recon (new)** — new `internal/recon` package. Detect frontend surface endpoints by category: `graphql`, `swagger`, `openapi`, `admin`, `debug`, `metrics`, `internal`, `staging`, `uat`. Detect cloud storage URLs: `s3.amazonaws.com`, `blob.core.windows.net`, `storage.googleapis.com`. Emits findings of type `attack_surface`.
- [x] **M6 → M7 wiring** — JS analyzer output feeds the source map analyzer; recon findings surface as `LOW`/`MEDIUM` severity `attack_surface` findings, not secret findings.

### V1.3 — Verification & Quality

Confirm findings, prove the rules are good, polish reporting.

- [x] **M4 Verification Engine (refactor)** — refactor `internal/validator/providers.go` (currently 349 lines) to explicit `POTENTIAL/LIKELY/VERIFIED` states. Add the spec's explicit endpoints: AWS `sts:GetCallerIdentity`, GitHub `GET /user`, Stripe `GET /v1/account`, OpenAI `GET /v1/models`. Verification is rate-limited, thread-safe, and opt-in only. New `--verify` CLI flag is added; existing `--validate` keeps its best-effort behavior across all 13 providers.
- [x] **M10 Rule Quality Testing (new)** — new `internal/ruletest` package. Positive corpus harness: 30 rules × 8 samples each. Negative corpus harness: 1000 lines from repo source files. Tracks precision, recall, false-positive rate, status. Rejects any rule below thresholds. (#5)
- [x] **M12 Reporting (extend)** — extend JSON, SARIF, and HTML formatters with `confidence`, `verification.status`, and `decoded_value_preview` fields. SARIF output includes `properties` for confidence and verification.

### V1.4 — Rule Quality Testing

Validate rule quality through automated test harness. Ships alongside V1.3.

- [x] **M10 Rule Quality Testing (new)** — new `internal/ruletest` package. Harness (Run/Report), corpus (LoadPositive/LoadNegative via //go:embed), report printer (status constants, PrintSummary returns int), CLI command (`syck ruletest` with --rule/--fp-threshold/--fn-threshold). Tests 30 high-signal rules with positive corpora (8 matching + 2 near-miss lines each) and 1000-line negative corpus from repo sources. All 30 rules pass at 100% precision/recall with default thresholds. CI workflow runs on every push/PR. (#5)

### V1.5 — FP Reduction & Performance

Cut false positives from base64-encoded media and prevent performance degradation on oversized lines.

- [x] **IsMediaToken filter** — new `entropy.IsMediaToken()` function detects 15 base64-encoded media formats (PNG, JPEG, GIF, SVG, WebP, WOFF, WOFF2, TTF, OTF, XML, ICO, TIFF LE/BE, BMP) via magic byte inspection of the first 20 base64 chars. Wired into the entropy token path in `scanContent` to filter false positives. 18 tests (15 positive + 3 negative + WebP regression). WebP special case verifies `WEBP` at byte offset 8 to avoid WAV/AVI false positives.
- [x] **MaxScanLineLen gate** — new `scanner.Config.MaxScanLineLen` field (0 = unlimited, default 100000) skips per-line scanning on lines exceeding the threshold. Debug log reports skipped lines (rate-limited to 10 per file). `--max-scan-line-len` CLI flag with default 100000. Three-layer performance gate: `--max-file-size` (file) → `--js-beautify` (structural) → `--max-scan-line-len` (safety net).

### V1.6 — Public Release

Polish the project for outside contributors and downstream users.

- [x] **README restructure** — badges (CI / Release / License / Go version / pre-1.0), "Why syck?" comparison table vs gitleaks / trufflehog / detect-secrets, real sample output (redacted), common workflows (pre-commit hook, GitHub Action, `.syckignore` generator, live validation), contributing guide. Pre-1.0 disclaimer badge + warning callout.
- [x] **CI hardening** — gofmt check in `ci.yml` (with `shell: bash` to handle Windows), Go module cache: true, `release.yml` workflow on `v*` tag.
- [x] **Release pipeline** — `.goreleaser.yaml` (linux/darwin/windows × amd64/arm64, CGO_ENABLED=0, archives, checksums, changelog filters), ldflags inject `main.version` / `main.commit` / `main.date` from `cmd.SetVersionInfo()`. `cmd/version.go` exposes the `syck version` subcommand.

### V1.7 — Operational Polish

Make `syck-go` easier to integrate into CI/CD pipelines, container environments, and long-running scans.

- [x] **Env var config (`SYCK_*`)** — every flag on the `scan` subcommand can be set via env var. Pattern: `SYCK_<CMD>_<FLAG>` (uppercase, dashes→underscores). Example: `SYCK_SCAN_SEVERITY=HIGH syck scan .`. Implementation: `cmd/env.go` walks flag set at run time, calls `cmd.Flags().Set()` for any matching env var. 5 unit tests cover: basic binding, empty env ignored, dash→underscore conversion, nil cmd safety, nil env safety.
- [x] **TUI progress bar (`--progress`)** — new `internal/progress` package wraps `schollz/progressbar/v3`. New `scanner.Config.Progress` callback field invoked per scanned file. `ScanPaths` uses atomic counters; `ScanReader` reports 1 file. Auto-disabled by `--quiet` or `--pipe`. Bar output goes to stderr so it doesn't pollute stdout for piping into other tools. 3 unit tests cover: tick counter, no-progress no-op, manual `Add()`.
- [x] **SARIF upload (`syck upload-sarif`)** — new subcommand posts SARIF JSON to GitHub Code Scanning API (`POST /repos/{owner}/{repo}/code-scanning/sarifs`). Flags: `--file`, `--repo`, `--commit`, `--base` (optional). Validates: `GITHUB_TOKEN` env present, `--repo` is `OWNER/REPO` format, file is JSON. 30-second timeout, sets `X-GitHub-Api-Version: 2022-11-28`. 4 unit tests cover: missing token, invalid repo format, non-JSON file, success path. Companion `docs/examples/github-actions.yml` shows full workflow.

### V1.8 — Endpoint Detection (JS-Aware Crawl + Risk Scoring)

Attack surface from frontend bundles: route extraction, source map harvesting, and juicy file probing.

- [ ] **Endpoint extraction** — `ExtractEndpoints` captures 21 endpoint patterns: 6 frontend router patterns (path:/, `<Route>`, `router.push`, `<Link>`, `<a>`), 4 GraphQL variants (`/graphql`, `/api/graphql`, `/query`, `/gql`), 3 OpenAPI patterns (`/openapi.json`, `/swagger.json`, `/v3/api-docs`), and 8 fetch/axios/XHR/WebSocket patterns.
- [ ] **Risk scoring** — `ComputeRiskScore` assigns 0-10 score using 19 group-weighted rules with `RequiresAPIPrefix` FP protection. Per-group max (not flat sum) prevents one category from dominating.
- [ ] **Source map harvesting** — crawler fetches `.js.map` alongside `.js` files, runs endpoint extraction over map content.
- [ ] **Juicy file detection** — probes 35 high-value paths (`/.env`, `/admin`, `/actuator/*`, `/metrics`, `/swagger.json`, etc.) via HEAD+GET with 1MB cap.
- [ ] **CLI** — `--min-endpoint-score N` (replaces deprecated `--sensitive-only`), `--no-juicy-files`, `--endpoints`.
- [ ] **Output** — risk_score field in all 6 formatters (JSON, text, SARIF, markdown, CSV, HTML).

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
collector_wiring: complete
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
