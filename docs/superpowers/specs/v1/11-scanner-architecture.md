# Module 11 — Scanner Architecture

> V1 pipeline: Collector → Decoder → Rule Engine → Entropy Engine → Correlation Engine → Verifier → Confidence → Reporter. Pure refactor of the 631-line `scanner.go`.

## Status

- **Tier:** P0
- **Phase:** V1.0
- **Action:** refactor
- **Owner:** unclaimed
- **Source package:** `internal/scanner/`

## Goal

Replace the monolithic `scanner.go` (631 lines) with the V1 pipeline. Each stage is a small, testable unit with a clear input/output contract. The public `Config` struct and CLI flag surface are preserved exactly. The pipeline ordering matches the V1 spec.

## Tasks

- [ ] Define a `Stage` interface: `Process(input []byte, ctx Context) ([]finding.Finding, error)`.
- [ ] Define a `Context` struct: file path, line number, rule set, entropy scorer, confidence scorer, correlator, verifier, config flags.
- [ ] Implement each stage as its own file:
  - `collector.go` — file walk, streaming for >1MB files, gzip detection (currently in `scanner.go:82-200`).
  - `decoder.go` — wraps `internal/decoder.DecodeAndRescan` and emits `DecoderFinding` records.
  - `rule.go` — runs `RuleSet.MatchAll` per line (currently in `scanner.go`).
  - `entropy.go` — runs entropy token scan and emits `EntropyFinding` records (currently in `scanner.go`).
  - `correlation.go` — wraps `internal/correlation.Correlator` (M5).
  - `verifier.go` — wraps `internal/validator.Validate` / `--verify` path (M4).
  - `confidence.go` — wraps `internal/confidence.Scorer` (M9). Runs last so all signals (regex, entropy, context, verification, credential pair) are available.
  - `reporter.go` — wraps dedup, downgrade, `.syckignore` filter, formatter dispatch (currently in `scanner.go` and `downgrade.go`).
  - `jsrecon.go` and `endpoints.go` — emit findings via the rule stage and the recon stage respectively.
- [ ] Add a `Pipeline` type: `Pipeline{Rules, Entropy, Correlator, Verifier, Confidencer, Config}`. `Pipeline.Run(paths []string) ([]finding.Finding, error)`.
- [ ] Preserve the public `Config` struct shape. Existing call sites in `cmd/scan.go` keep working.
- [ ] Concurrency: the existing `ThreadPoolExecutor` pattern (`scanner.go:82-108`) moves into the `Pipeline` type. Use `errgroup` instead of bare `sync.WaitGroup` for cleaner error propagation.
- [ ] Unit tests: each stage has a focused test. The full pipeline has a regression test that runs the V6 benchmark corpus and asserts the same 17 correct / 0 wrong result.

## Exit Criteria

- [ ] `go test ./internal/scanner/...` passes.
- [ ] `go test ./...` passes across the whole repo.
- [ ] `internal/scanner/scanner.go` is reduced to under 100 lines (entry point + `Config` struct).
- [ ] The V6 benchmark (17 correct, 0 wrong) still produces 17 correct-rule matches after the refactor.
- [ ] All existing CLI flags still work. Run `./syck scan --help` and confirm the flag list is unchanged.
- [ ] `--validate` still produces the same result as before the refactor.
- [ ] Memory profile is no worse than the current binary on a 100MB+ repo scan.

## Dependencies

- Depends on: M1, M2, M3, M4, M5, M6, M7, M8, M9 (every other module feeds the pipeline)
- Depended on by: nothing — this is the root in the dependency graph

## Notes for implementer

- The refactor is the riskiest single piece of V1 work. Land it behind a `V1_PIPELINE=1` build tag for the first PR, then remove the tag once it stabilizes.
- Do not change `Config` field order or names. The CLI flag surface depends on struct tags (`mapstructure:"..."` via Viper).
- The `Pipeline.Run` method is the only entry point `cmd/scan.go` needs. The current `ScanPaths`, `ScanFile`, `ScanReader`, `ScanURLs`, `ScanContent` API should be preserved as thin wrappers that build a `Pipeline` and call `Run`.
- The `Context` struct is per-file. Do not share it across goroutines. Each file gets its own `Context` instance.
- Findings emitted by every stage flow into a shared `[]finding.Finding` per file. Dedup, downgrade, and `.syckignore` filtering happen in the Reporter stage.
