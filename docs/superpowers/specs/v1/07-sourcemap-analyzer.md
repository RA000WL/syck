# Module 07 — Source Map Analyzer

> Download, reconstruct, and scan original source from `.js.map`, `.map.gz`, and inline source maps. Link findings back to the original source file.

## Status

- **Tier:** P2
- **Phase:** V1.2
- **Action:** new
- **Owner:** unclaimed
- **New package:** `internal/sourcemap/`

## Goal

JavaScript bundles often ship with source maps that, when downloaded, reveal the original unminified source. The source map analyzer fetches those maps (or extracts inline `//# sourceMappingURL=...` references), reconstructs the original source, scans it for secrets, and emits findings tagged with the original source file path and line number.

## Tasks

- [ ] Create `internal/sourcemap/analyzer.go` with the public `Analyzer` type.
- [ ] Detect source map references in `.js` content: `//# sourceMappingURL=foo.js.map` and `//# sourceMappingURL=data:application/json;base64,...` (inline).
- [ ] For local maps (path on disk), read the file. For URL maps, fetch via `net/http` with a configurable timeout and the existing crawler rate limiter.
- [ ] Support gzip-encoded maps (`.map.gz`) by sniffing the magic bytes.
- [ ] Parse the source map JSON (`version`, `sources`, `sourcesContent`, `mappings`).
- [ ] For each `sources` entry, build the reconstructed file content from `sourcesContent` (or fetch it if absent).
- [ ] Hand the reconstructed content to the regular scanner pipeline (M11). Findings are tagged with the original source path and the original line number.
- [ ] Extract secondary signals from reconstructed source:
  - `.env` references (string literals like `process.env.X` or `import.meta.env.X`)
  - TODO/FIXME/HACK/XXX comments
  - Dead code (unreachable branches, unused exports) — emit as `attack_surface` findings, not secret findings
  - Debug endpoints (`/debug`, `/_debug`, `/admin`, `/internal`)
- [ ] Unit tests: a fixture `.js.map` reconstructs to the expected original source; inline data-URI maps are detected and decoded.

## Exit Criteria

- [ ] `go test ./internal/sourcemap/...` passes.
- [ ] A fixture bundle + fixture source map produces findings tagged with the original source file path.
- [ ] An inline `//# sourceMappingURL=data:application/json;base64,...` reference in a fixture is detected and decoded without making a network request.
- [ ] A `.map.gz` fixture is detected, gunzipped, and parsed.
- [ ] URL maps are only fetched when the URL host passes the existing crawler scope filter.
- [ ] No regression: the existing crawler tests still pass.

## Dependencies

- Depends on: M6 (JS analyzer produces the `sourceMappingURL` references), M11 (scanner pipeline runs the regular scan on reconstructed source), M8 (debug endpoint extraction feeds the recon engine)
- Depended on by: nothing — this is a leaf in the dependency graph

## Notes for implementer

- Use a vendored source map library or implement just enough VLQ decoding. The `github.com/go-sourcemap/sourcemap` package is small and well-tested; check whether it can be vendored or if we need a custom impl.
- Source map fetching must respect `--rate-limit`, `--scope`, and `--ignore-robots`. Reuse the crawler package, do not reimplement.
- Findings from reconstructed source have a `SourceMapOrigin` field on the finding: `{ OriginalFile, OriginalLine, BundleFile, BundleLine }`. The formatters (M12) surface this.
- Be careful with large bundles: a single 10MB minified bundle can expand to 50MB+ of reconstructed source. Stream line-by-line into the scanner pipeline; do not load the whole thing into memory.
- Source map fetching is opt-in via a new `--sourcemap` CLI flag. Default off.
