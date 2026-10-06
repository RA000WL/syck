# SYCK Batch 4 Refactor & Health — Design Spec

Date: 2026-10-06
Path chosen: A test-gated refactor
Status: awaiting user review before implementation plan

## 1. Intent

Final batch in the phased plan. Batches 1–3 (hardening, detection
quality, performance) are merged locally with verified gates. Batch 4
closes structural debt safely: characterize before refactoring, unify
duplicated detection, and sweep the leftovers queued by earlier
batches.

Success: the four untested packages gain real tests; a parity harness
proves every refactor changed no findings; God files are split without
behavior change; duplicated logic is unified; queued debt is retired.

## 2. Sub-batch scopes (approved)

### 4a — Characterization tests and the parity harness

- First tests for the four zero-test packages: `config`,
  `internal/externaltools`, `internal/gitscan`, `internal/json_scanner`.
- A parity harness: committed golden fixtures plus a test that pins
  finding count and sorted `(rule, severity, file)` triples, with an
  `-update` flag for intentional regeneration.

4a must land before 4b/4c/4d. It is the contract those phases are
verified against.

### 4b — God files

- `internal/scanner/scan.go` (1261 lines) split along existing seams
  into `scan_paths.go`, `scan_file.go`, `scan_stream.go`,
  `scan_read.go`, `scan_content.go`, leaving `scan.go` as the dispatch
  surface.
- `cmd/scan.go` (849 lines) split into `scan_config.go` (flag vars and
  `init()`), `scan_run.go` (`runScan`), and `scan_postprocess.go`
  (dedup, filtering, validation, webhook, fail-on).

Pure moves. No signature changes.

### 4c — Deduplicate detection and resolve V1/V6

- One shared internal-URL / private-IP matcher (`internal/internalurl`)
  replacing the three regex sets in `internal/endpoints/extract.go`,
  `internal/jsanalysis/analyze.go`, and
  `internal/recon/detector_internal.go`. It reuses `netguard`'s CIDR
  classification rather than adding a fourth notion of "internal".
- Resolve the V1 `Pipeline`: it is reachable only from
  `internal/scanner/pipeline_test.go`. Either delete it and the stages
  only it uses, or keep it and label it test-only in the package doc.

### 4d — Queued leftovers

Retire the debt accumulated during Batches 1–3:

- Dead code: `crawler.BodyPool` (zero consumers since Batch 3 Task 5),
  `crawler.visitedCount` (test-only since Task 6).
- Duplicated SQLite pragma setup: one shared helper instead of the copy
  in `correlator` and `crawler`.
- Concurrency clamps: `parambrute` and `crawler` still use a literal
  `10`; move them to the shared `EffectiveWorkers` policy.
- `ConfidenceStage` recompute drift (dead path, fix or delete with V1).
- Non-secret findings (endpoints, tech, juicy files) off the unified
  confidence scale — either bring them onto it or document the exclusion.
- `url_secrets.go` entropy floor and the local floors in
  `json_scanner` / `jsrecon`: route through the shared
  `decoder.RuleEntropyFloor` where a rule object exists.
- `ScanReader` hard-errors above its buffer with no stdin fallback.

Out of scope: any rule-content change, any new detection capability,
any user-visible behavior change. Batch 4 changes structure, not
findings — with the one deliberate exception of retiring the
`ConfidenceStage`/V1 dead code, which changes nothing observable.

## 3. Component changes (approved)

- **4a:** new test files only: `config/config_test.go`,
  `internal/externaltools/tools_test.go` (argv building, no subprocess),
  `internal/gitscan/scanner_test.go` (temp `git init` repo, skip if git
  is absent), `internal/json_scanner/scanner_test.go`.
  `internal/scanner/parity_test.go` plus `internal/scanner/testdata/parity/`
  fixtures covering JS, YAML, JSON, `.env`, Go, and Python; the test
  compares against a committed golden file and supports `-update`.
- **4b:** pure moves within the same packages; every symbol keeps its
  signature. `scan.go` retains only dispatch.
- **4c:** new `internal/internalurl` package owning the shared matcher;
  the three consumers call it. V1 resolution per the sub-batch scope.
- **4d:** as enumerated above.

## 4. Data flow, errors, testing (approved)

No new pipeline stages. Public entry points keep their signatures:
`ScanPaths`, `ScanFile`, `ScanURLs`, `ScanContent`, `ScanReader`.

The parity harness is the contract: if 4b–4d change any finding, parity
fails. The response is revert-to-last-green, not silent golden
regeneration; regeneration is reserved for a deliberate, justified
change with the reason in the commit body.

4a's new tests pin existing error behavior: `config.Load` on a bad
path, `gitscan` on a non-repo, `externaltools` on a missing binary.
The Batch 3 contract that SQLite and `RecordFileMtime` errors stay
non-fatal and `cfg.Debug`-logged is re-verified, not changed.

Gates per task: `go test -race ./...`, `ruletest 40/40`, `gofmt`,
`go vet`, plus parity green for every task from 4b onward.

## 5. Risks

- 4b is the highest-risk phase: pure moves through a 1261-line file
  where an unnoticed change alters findings. Mitigation is parity plus
  revert-to-last-green, not golden regeneration.
- The parity fixtures encode current behavior, including known
  weaknesses. That is the point (it detects change), but it must not be
  read as an endorsement of the golden output.
- Deleting V1 `Pipeline` removes the only caller of several stages. If
  any stage has real behavior the CLI path needs, deletion is wrong —
  so 4c verifies call sites before removing anything.
- 4d's confidence-scale question (bring non-secret findings onto the
  scale vs document the exclusion) changes visible output either way.
  It is the one item in Batch 4 that needs an explicit ruling during
  implementation rather than a mechanical fix.
- Test-only `gitscan` coverage shells out to `git`; the suite must skip
  cleanly when git is unavailable rather than fail CI.