# V1.2 — Frontend Reconnaissance Architecture

> Design decisions for M6 (JS Analyzer), M7 (Source Map Analyzer), and M8 (Frontend Recon).
> Extended from specs: `06-js-analyzer.md`, `07-sourcemap-analyzer.md`, `08-frontend-recon.md`.

## Status

- **Phase:** V1.2
- **Build order:** M6 → M8 → M7
- **Pipeline integration:** Pre-scan collector phase (Option B)

## Architecture

### Pre-Scan Collector Phase

A `CollectorStage` runs *before* the per-line loop in `ScanString`, receiving full file content:

```
ScanString V1.2:
  Collector.Process(content, path) → []finding.Finding    [NEW]
  for each line:
    Rule → Decoder → Entropy
  all = append(collector findings, line-level findings)
  Correlation → Verifier → Confidence → Reporter
```

File-type routing inside the collector:

| Extension | Analyzers |
|---|---|
| `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.mjs` | M6 + M8 + sourceMappingURL detection |
| `.map` | M7 (source map reconstruction) |
| All files | M8 (URL extraction from any content) |

`--sourcemap` CLI flag (default off) gates M7 execution.

### Pipeline Struct

```go
type Pipeline struct {
    Rule        *RuleStage
    Collector   *CollectorStage   // NEW — pre-scan collector
    Decoder     *DecoderStage
    Entropy     *EntropyStage
    Correlation *CorrelationStage
    Verifier    *VerifierStage
    Confidence  *ConfidenceStage
    Reporter    *ReporterStage
}
```

### M6: JS Analyzer (`internal/jsrecon/`)

**New file:** `analyze.go` (alongside existing `reconstruct.go`)

**Public entry point:**
```go
type JSRequest struct {
    Endpoint   string
    Method     string
    Headers    map[string]string
    Domains    []string
    APIKeys    []string
    SourceFile string
    SourceLine int
}

func Analyze(content string, file string) []JSRequest
```

**5 regex-based detectors:**
1. `fetch(url, {method, headers})` — modern browser/Node.js HTTP
2. `axios.{method}(url, config)` — Vue/Nuxt ecosystem
3. `new XMLHttpRequest()` + `.open()` + `.setRequestHeader()` — legacy XHR
4. Apollo Client + GraphQL endpoint patterns
5. `Authorization` header parsing: Bearer, Basic, custom schemes

**Scope: best-effort signal, not thorough.** Minification collapses variable names (`fetch(a,{method:b})`), so regex detection will miss paths it can't statically resolve. Accept this as signal — enough to flag *some* endpoint URLs and API keys from readable bundles. Users of minified code should enable `--sourcemap` for full coverage.

**Method default:** `fetch(url)` with no options object defaults to GET (HTTP). Findings log assumption so consumers can distinguish detected vs assumed methods.

**Collector mapping:** The collector does NOT emit findings for API keys — they are caught by the regular rule engine scanning the raw JS content (per M6 spec exit criteria). All `.Endpoint` values feed into M8's URL list for categorization.

### M7: Source Map Analyzer (new `internal/sourcemap/`)

**Custom VLQ decoder** — no external dependency. Budget ~120 lines including property-based tests. Handle edge cases: multi-segment columns, null mappings (`;` with no segments), out-of-range indices, corrupt/truncated data. Return partial results on error (don't fail the whole analysis).

**3 files:**
- `analyzer.go` — `Analyzer` type, `DetectRefs`, `Fetch`, `Reconstruct`
- `sourcemap.go` — `SourceMapRef`, `SourceMap` structs
- `vlq.go` — VLQ segment decoding

**Features:**
- Inline `data:application/json;base64,...` detection (no network)
- File-based `.map` reads
- URL-based map fetching (respects crawler rate limiter + scope)
- Gzip detection via magic bytes `0x1F 0x8B`
- Reconstructed source scanned through regular pipeline with `OriginalSource` annotation

**Secondary signals from reconstructed source:**
- `process.env.X` / `import.meta.env.X` references
- TODO/FIXME/HACK/XXX comments
- Debug endpoints → feed into M8
- Dead code → `attack_surface` findings

### M8: Frontend Recon (new `internal/recon/`)

**Reuses** `internal/endpoints/extract.go` for URL extraction (no duplication).

**Structs:**
```go
type Detector interface {
    Detect(urls []string) []SurfaceFinding
}

type SurfaceFinding struct {
    URL        string
    Category   string          // one of 10 categories
    Severity   finding.Severity
    Confidence int
    Source     string
    Line       int
}

type Registry struct {
    detectors []Detector
}
```

**10 pattern-based category detectors** (hardcoded regex, no YAML config):

| Category | Severity | Pattern |
|---|---|---|
| GraphQL | HIGH | `/graphql`, `/gql`, `?query=` |
| Swagger/OpenAPI | MEDIUM | `/swagger.json`, `/api-docs`, `/openapi.json` |
| Admin | HIGH | `/admin`, `/panel`, `/console` |
| Auth | MEDIUM | `/login`, `/oauth`, `/token`, `/authorize` |
| Debug | LOW | `/debug`, `/healthz`, `/readyz` |
| Metrics | MEDIUM | `/metrics`, `/prometheus` |
| Internal | LOW | `/internal`, `/private`, `internal.` |
| Staging/UAT | LOW | `/staging`, `/dev`, `/test` |
| Storage | HIGH | S3, Azure Blob, GCS URLs |

`attack_surface` findings output as `finding.Finding` entries with `Type: "attack_surface"`.

### Testing Strategy

Each module has its own test fixtures:

- **M6:** A JS fixture file with `fetch`/`axios`/XHR/Apollo/GraphQL calls; verify `Analyze` produces correct `JSRequest` entries
- **M7:** A fixture `.js.map` with known VLQ mappings + inline data-URI map + `.map.gz`; verify reconstruction matches expected source. Track memory pressure — reconstructed source can be 5-10x the map size
- **M8:** URL fixtures for each of the 10 categories; verify categorization + no false positives
- **Integration:** A combined test with a JS bundle that exercises M6 → M8 → collector → pipeline end-to-end

### What's Not Changing

- All existing `Scan*` method signatures
- `scanner.Config` fields (no new fields; `--sourcemap` is pipeline-level)
- `finding.Finding` struct (attack_surface reuses existing Type/Confidence fields)
- Existing `decoder.Flags`, `decoder.Registry`, `confidence.Band`
- V1.0/V1.1 public surface
