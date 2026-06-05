# Module 12 — Reporting

> Extend JSON, SARIF, HTML, Markdown, CSV formatters with confidence, verification status, and decoded value preview.

## Status

- **Tier:** P0
- **Phase:** V1.3
- **Action:** extend
- **Owner:** unclaimed
- **Source package:** `internal/formatters/`

## Goal

Every formatter surfaces the new V1 fields (`confidence`, `verification.status`, `decoded_value_preview`) consistently. The SARIF formatter emits GitHub Code Scanning-compatible output with `security-severity` and `properties` for confidence and verification. The HTML formatter renders the new fields in a dark-themed report.

## Tasks

- [ ] Extend `finding.Finding` with: `Confidence string` (LOW/MEDIUM/HIGH/CRITICAL from M9), `VerificationStatus string` (POTENTIAL/LIKELY/VERIFIED from M4), `DecodedValuePreview string` (first 64 chars of decoded content, from M3).
- [ ] JSON formatter (`formatters/json.go`, 84 lines): add the three new fields to the emitted JSON object.
- [ ] SARIF formatter (`formatters/sarif.go`, 175 lines):
  - `security-severity` is computed from severity, **not** confidence (preserve GitHub Code Scanning semantics).
  - Add `properties.confidence` and `properties.verificationStatus` to each `result`.
  - Add `properties.sourceMapOrigin` when present (from M7).
- [ ] HTML formatter (`formatters/html.go`, 108 lines): add a `Confidence` badge, a `Verification` status badge, and a collapsible `Decoded preview` section per finding.
- [ ] Markdown formatter (`formatters/markdown.go`, 61 lines): add a column or inline tag for confidence and verification.
- [ ] CSV formatter (`formatters/csv.go`, 47 lines): add `confidence`, `verification_status`, `decoded_value_preview` columns.
- [ ] Text formatter (`formatters/text.go`, 145 lines): color the confidence band and print verification status inline.
- [ ] Unit tests: each formatter renders a finding with all three new fields populated. Snapshot the output and check for regressions.
- [ ] Update the README with examples of the new output for at least one formatter (HTML is best for screenshots).

## Exit Criteria

- [ ] `go test ./internal/formatters/...` passes.
- [ ] JSON output for a finding includes `confidence`, `verification_status`, and `decoded_value_preview` fields.
- [ ] SARIF output for a finding includes `security-severity` (from severity) and `properties.confidence` / `properties.verificationStatus`.
- [ ] HTML output renders the new fields in the dark-themed template.
- [ ] CSV output includes the three new columns.
- [ ] The text formatter still fits in a 120-column terminal without wrapping.
- [ ] No regression: a V6 finding rendered before the change still renders correctly (snapshot test).

## Dependencies

- Depends on: M4 (verification status), M7 (source map origin), M9 (confidence)
- Depended on by: nothing — this is a leaf in the dependency graph

## Notes for implementer

- `finding.Finding` already has `Severity`. Add `Confidence`, `VerificationStatus`, `DecodedValuePreview` as plain string fields. JSON tags use snake_case to match the existing fields.
- The HTML formatter uses `html/template`. Add the new badges to the existing template; do not rewrite the whole template.
- SARIF `security-severity` is a float in [0, 10] in the spec. Map severity: `CRITICAL=9.5`, `HIGH=7.5`, `MEDIUM=5.0`, `LOW=2.5`, `INFO=0.5`. This is unchanged from the current code.
- The text formatter already does ANSI color. Add a separate color for confidence (e.g. dim for LOW, normal for MEDIUM, bold for HIGH, bright-red for CRITICAL).
- Snapshot tests: use `github.com/google/go-cmp` if it is already a dependency; otherwise simple `bytes.Equal` against a `testdata/<formatter>/<case>.golden` file.
- Document the new output fields in the README "Output Formats" section.
