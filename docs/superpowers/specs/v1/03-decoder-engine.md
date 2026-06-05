# Module 03 — Decoder Engine

> Multi-layer decoding of base64, hex, unicode, URL, gzip, JWT, and JS-runtime hooks (atob, Buffer.from). Cap recursion at 3.

## Status

- **Tier:** P0
- **Phase:** V1.1
- **Action:** extend
- **Owner:** unclaimed
- **Source package:** `internal/decoder/`

## Goal

Extend the existing decoder pipeline with JWT payload split, JS-runtime decode hooks (`atob()`, `Buffer.from(x, 'base64')`), and a thread-safe decoder registry. Cap recursion depth at 3 per the V1 spec (current code uses 4).

## Tasks

- [ ] Cap `MaxRecursionDepth` at 3. Update `pipeline.go:14`.
- [ ] Add JWT decoder: split on `.`, base64url-decode the payload (middle segment), and emit a `jwt_<claim>` decoded text.
- [ ] Add JS-runtime hooks: when the JS analyzer (M6) reconstructs strings, recognize `atob("...")`, `Buffer.from("...", "base64")`, `Buffer.from("...", "hex")` and emit the decoded text as a candidate.
- [ ] Make the decoder registry thread-safe: add a `sync.RWMutex` and convert `activeDecoders` to a method on a `Registry` type.
- [ ] Add `DecodeBase64URL` (URL-safe alphabet with `-_`).
- [ ] Add `DoubleBase64` detector: a string that base64-decodes to another string that also looks base64. Apply the same cap.
- [ ] Unit tests: each decoder produces expected output; pipeline never recurses past depth 3; JWT decoder splits a real JWT; thread-safety test with `-race`.

## Exit Criteria

- [ ] `go test ./internal/decoder/... -race` passes.
- [ ] `MaxRecursionDepth == 3` enforced — a 4-level nested base64 string does not produce a 4th-level decoded finding.
- [ ] A standard 3-segment JWT decodes to its payload JSON and re-feeds the pipeline.
- [ ] `atob("aGVsbG8=")` produces `"hello"` as a decoded candidate when fed in via the JS-reconstructed text path.
- [ ] `Registry` can be safely used from multiple goroutines (race detector clean).
- [ ] No change to `DecodeAndRescan` signature — `internal/scanner/scanner.go` calls it as-is.

## Dependencies

- Depends on: M2 (uses entropy helpers for post-decode entropy gate), M6 (JS analyzer feeds `atob`/`Buffer.from` candidates)
- Depended on by: M5 (correlation engine operates on decoded findings), M11 (scanner pipeline calls `DecodeAndRescan`)

## Notes for implementer

- Existing decoders (`decoders.go`) stay. New ones are additive entries in the registry.
- The `decoderEntry` type is unexported. The new `Registry` type should expose `Register(name string, d Decoder)` and `Active(flags Flags) []Decoder`.
- Use the standard library `encoding/base64` `RawURLEncoding` variant for URL-safe and JWT segments.
- Watch for infinite recursion: a string that decodes to itself (rare but possible with all-zero bytes). The depth cap is the safety net, but a length cap on the output is also a good idea.
