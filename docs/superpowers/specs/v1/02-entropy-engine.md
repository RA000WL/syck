# Module 02 — Entropy Engine

> Shannon, base64, hex, and JWT entropy helpers. Per-alphabet entropy calculation with configurable thresholds.

## Status

- **Tier:** P0
- **Phase:** V1.0
- **Action:** extend
- **Owner:** unclaimed
- **Source package:** `internal/entropy/`

## Goal

Extend the existing Shannon entropy with alphabet-specific variants so the scanner can pick the right entropy calculation for the token it sees. A base64 string should not be scored the same as a hex string, and a JWT segment should be scored against a 64-char alphabet.

## Tasks

- [ ] Add `Base64Entropy(s string) float64` — Shannon over the base64 alphabet, normalized to bits per character.
- [ ] Add `HexEntropy(s string) float64` — Shannon over `[0-9a-f]` (case-insensitive), normalized to 4.0 max.
- [ ] Add `JwtEntropy(s string) float64` — Shannon over the URL-safe base64 alphabet (`[A-Za-z0-9_-]`), normalized to 6.0 max.
- [ ] Add `Alphabet` enum: `AlphabetUnknown`, `AlphabetLowerHex`, `AlphabetUpperHex`, `AlphabetBase64`, `AlphabetBase64URL`, `AlphabetJWT`.
- [ ] Add `DetectAlphabet(s string) Alphabet` based on character set and length heuristics.
- [ ] Add `EntropyByAlphabet(s string, a Alphabet) float64` that dispatches to the right helper.
- [ ] Update `IsEntropyTokenMatch` to call the alphabet-specific helper and apply the rule's `entropy_threshold` (from M1) when available, falling back to the current 4.5 default.
- [ ] Unit tests: known strings produce expected entropy within 0.01; alphabet detection is correct on the test corpora in `testdata/`.

## Exit Criteria

- [ ] `go test ./internal/entropy/...` passes.
- [ ] `Base64Entropy("aGVsbG8=")` returns a value within 0.01 of the reference.
- [ ] `HexEntropy("deadbeefcafe")` returns a value within 0.01 of the reference.
- [ ] `DetectAlphabet` correctly identifies the alphabet for a 50-token test set in `testdata/alphabet_cases.txt`.
- [ ] `IsEntropyTokenMatch` continues to accept the same real tokens it accepts today (regression test against the existing test corpus if present).
- [ ] No change to the public API consumed by `internal/scanner/scanner.go` and `internal/decoder/pipeline.go`.

## Dependencies

- Depends on: nothing (uses `math` and `regexp` already in the package)
- Depended on by: M9 (confidence adds entropy signal), M6 (JS analyzer uses JWT entropy for token scanning)

## Notes for implementer

- Keep `Shannon(data)` as the underlying primitive. The new helpers are thin wrappers that filter the input alphabet first or normalize the output range.
- `IsLowEntropy` and `LikelySecret` stay as-is. The new helpers are additive.
- Reference values: `Base64Entropy("a") = 0`, `Base64Entropy("ab") = 1.0`, `HexEntropy("01") = 1.0`, `JwtEntropy("--") = 1.0`. Use these for sanity checks.
