# SYCK Batch 4c Shared Internal-URL Predicates — Design Spec

Date: 2026-10-06
Path chosen: conservative (extract shared predicates; document V1; delete nothing)
Status: awaiting user review before implementation plan

## 1. Intent

Batch 4b split the two God files (merged locally, parity-verified). Batch4c
removes the *conceptual* duplication left in internal-URL detection, and
resolves the V1-pipeline question without deleting capability.

Success: exactly one definition of "private/internal" in the codebase;
three call sites delegate to it; nothing observable changes; parity green.

## 2. Correction to the original audit (important)

The Batch 1 audit described `internal/endpoints/extract.go`,
`internal/jsanalysis/analyze.go`, and `internal/recon/detector_internal.go`
as "three regex sets for 'is this internal?'". That was an oversimplification.
They are three *different tasks* that share vocabulary:

- `recon/detector_internal.go` — a **classifier** over whole URLs, returning
  one of 7 categories (`internal`, `internal_host`, `private_ip`,
  `localhost`, `cloud_metadata`, `container_service`, `sensitive_port`).
- `jsanalysis/analyze.go` — **extraction** from JavaScript source
  (`internal: "..."` config values, `localhost:8080`).
- `endpoints/extract.go` — one pattern among ~30 in an endpoint-extraction
  list.

Collapsing them into one function would have destroyed behavior. 4c
therefore extracts only the genuinely shared *predicates*; the task-specific
patterns stay where they are.

## 3. Component changes (approved)

### New package `internal/internalurl`

Exports single-source predicates over a raw URL or host string:

- `IsPrivateHost(rawURL string) bool` — private IPv4 ranges (10/8,
  172.16/12, 192.168/16)
- `IsLoopback(rawURL string) bool` — `127.0.0.0/8`, `::1`, `localhost`
- `IsCloudMetadata(rawURL string) bool` — `169.254.169.254`,
  `metadata.google.internal` (with and without trailing dot)
- `IsInternalHost(rawURL string) bool` — `internal.`, `corp.`, `.local`
  suffixes, k8s-style `*.svc` / `*.cluster` names
- `IsInternalPath(rawURL string) bool` — `/internal`, `/private`,
  `/debug`, `/admin`, `/staging`, …
- `IsSensitivePort(rawURL string) bool` — database/service ports
  (3306, 5432, 6379, 27017, 9200, …)

**Reuse, do not reimplement:** the CIDR classification comes from
`internal/netguard` (Batch 1), which already owns the authoritative
private/loopback/link-local/metadata checks. If `netguard` cannot export
what is needed without an import cycle, `internalurl` becomes the lower
layer and `netguard` delegates to it — one direction only, decided during
implementation and recorded in the commit body.

### Call sites

- `internal/recon/detector_internal.go` — keeps `classifyInternal` and its
  7-category contract exactly as-is; each `if` delegates to the matching
  predicate. **Category names and severities must not change** — they are
  user-visible in output.
- `internal/jsanalysis/analyze.go` — keeps `internalServiceRE` and its
  `localhostRE` (they extract values, they do not classify); the loopback
  test delegates to `internalurl.IsLoopback`.
- `internal/endpoints/extract.go` — unchanged. Its single pattern is
  endpoint *extraction*, not classification; sharing it would be the
  behavior-destroying merge this spec rejects.

### V1 pipeline

`internal/scanner/pipeline.go` and the `stage_*.go` files are reachable
only from `internal/scanner/pipeline_test.go` — never from the CLI. The
stages are **not** all redundant, and the two cases differ:

- `CorrelationStage` is the **only** route to `internal/correlation`. Nothing
  outside `NewPipeline` constructs a `Correlator`, so the correlation
  detectors do not run on the CLI path at all. This is a real functional gap.
- `VerifierStage` performs live secret validation via `internal/validator`.
  The CLI performs the **same** validation and sets the same states, but only
  behind `--validate` / `--verify` (`cmd/scan_run.go`). So this capability is
  **duplicated, not missing** — the stage is unreachable but its effect is
  already reachable another way.

> Correction (2026-10-06, during Task 6): an earlier draft of this spec said
> the CLI invokes "neither". That was wrong about `VerifierStage` — the CLI
> does call `validator.Validate` directly. Caught by the Task 6 implementer,
> who declined to write the false claim into the package doc.

Decision: **delete nothing.** Add an explicit note to the
`internal/scanner` package doc stating that `Pipeline` and the V1 stages
are test-only, are not on the CLI scan path, and that the CLI uses the V6
entry points. This resolves the ambiguity that produced the V1/V6
contradiction between `scanner.go`'s comment, `pipeline.go`, and
ARCHITECTURE.md.

## 4. Data flow, errors, testing

No observable behavior change. `classifyInternal` returns the same
category for the same URL; severities unchanged; the `jsanalysis` findings
are unchanged. The parity harness is the gate.

Testing:
- `internal/internalurl/netguard_test.go`-style table tests pinning each
  predicate against known inputs, including the exact cases Batch 1's
  `netguard` tests already assert (10/8, 172.16/12, 192.168/16, loopback,
  unspecified, `169.254.169.254`, `metadata.google.internal` ± trailing dot).
- A `classifyInternal` characterization test in `internal/recon` pinning
  the current category for each of the 7 categories **before** the
  refactor, so the delegation is provably behavior-neutral.
- Parity harness green throughout.

Gates: `go build`, `gofmt -l .` empty, `go vet ./...`,
`go test -race ./...`, `ruletest 40/40`, parity PASS.

## 5. Risks

- **Direction of the netguard/internalurl dependency is a design decision
  that surfaces during implementation.** Both packages must not import each
  other; exactly one owns the CIDR list. Getting it backwards creates a
  cycle; duplicating it recreates the problem this sub-batch exists to fix.
- `classifyInternal` category strings are user-visible output. A typo in a
  delegation silently changes recon output; the characterization test is
  what prevents that.
- Making the V1 pipeline "test-only" in docs could read as a judgment that
  it should be deleted later. The note should say what it is without
  prescribing removal.
- `IsLoopback` accepting the literal `localhost` string, while `netguard`
  deliberately does not (DNS names are not IPs) — the two layers must agree
  on which notion of loopback they use, or the same URL classifies
  differently in different parts of the tool.