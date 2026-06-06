# V1.5 — FP Reduction & Performance

Bug bounty readiness: reduce false positives (base64-encoded media) and improve scanning performance on large JS bundles.

## Media Token Filter

**Problem:** Entropy scanning flags base64-encoded images, fonts, and SVGs embedded in JS/CSS as high-entropy secrets. These are never real secrets.

**Solution:** Add `IsMediaToken(tok string) bool` in `internal/entropy/` that base64-decodes the candidate token and checks the first bytes against known media magic numbers:

| Format | Magic Bytes | Base64 Starts With |
|--------|-------------|-------------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `iVBOR` |
| JPEG | `FF D8 FF` | `/9j/` |
| GIF87a | `47 49 46 38 37 61` | `R0lGOD` |
| GIF89a | `47 49 46 38 39 61` | `R0lGOD` |
| WebP | `52 49 46 46` + `WEBP` at byte 8 | `UklGR` |
| SVG/XML | `3C 3F 78 6D 6C` (<?xml) or `3C 73 76 67` (<svg) | `PD94bWwg` or `PHN2Zy` |
| ICO | `00 00 01 00` | `AAAB` |
| TIFF (LE) | `49 49 2A 00` | `SUkq` |
| TIFF (BE) | `4D 4D 00 2A` | `TU0A` |
| BMP | `42 4D` | `Qk` |
| WOFF | `77 4F 46 46` | `d09GMg` or `T1Rf` |
| WOFF2 | `77 4F 46 32` | `d09G` |
| TTF | `00 01 00 00` | `AAEAAA` |
| OTF | `4F 54 54 4F` | `T1RUTw` |

**Location:** `internal/entropy/entropy.go` — new exported function.

**Optimization:** Only decode the first 16 bytes of the token (enough for the longest magic sequence) to avoid full-token allocation:
```go
func IsMediaToken(tok string) bool {
    // Pad to multiple of 4 for valid decode
    padded := tok
    switch len(padded) % 4 {
    case 2: padded += "=="
    case 3: padded += "="
    }
    // Decode only enough bytes for longest magic sequence (PNG: 8 bytes)
    sliceLen := min(len(padded), 20) // 20 base64 chars → 15 decoded bytes
    sliceLen -= sliceLen % 4         // align to base64 group boundary
    decoded, err := base64.StdEncoding.DecodeString(padded[:sliceLen])
    if err != nil || len(decoded) < 4 {
        return false
    }
    // check magic numbers on decoded[:min(len(decoded), 12)]
    ...
}
```

**Integration points (`internal/scanner/scan.go`):**

1. **Entropy scan in `scanContent`** — after `if !entropy.IsEntropyTokenMatch(tok) { continue }`, add:
   ```go
   if entropy.IsMediaToken(tok) {
       continue
   }
   ```

2. **No changes needed** for the rule-based scan path — media tokens rarely match secret rules.

**Edge cases:**
- Token is not valid base64 → return false (let it through)
- Token decodes to <4 bytes → return false
- Token decodes to a known magic number → return true (skip)
- Try padding-insensitive decode (handle missing `=` padding common in URL contexts)

## Max Scan Line Length

**Problem:** Minified JS bundles contain multi-megabyte single lines. Running 150+ regexes + entropy scan on these is extremely slow. After beautification splits content, remaining long lines are almost always embedded encoded data.

**Solution:** Skip per-line rule matching and entropy scanning on lines exceeding `MaxScanLineLen` bytes.

**Config:** Add to `scanner.Config`:
```go
MaxScanLineLen int  // default 100000 (100KB), 0 = unlimited
```

**Behavior:**
- `scanContent` checks line length before the rule/entropy loops
- Lines > `MaxScanLineLen` are **skipped entirely** for per-line scanning
- CollectorStage (endpoint extraction, JS analysis, recon URLs) runs on full content regardless — always catches exposed endpoints
- Beautifier runs before per-line scan, so most legitimate code is already on short lines

**Integration (`internal/scanner/scan.go`):**
```go
// Inside scanContent, before the line loop:
for lineNum, line := range lines {
    if cfg.MaxScanLineLen > 0 && len(line) > cfg.MaxScanLineLen {
        continue  // skip per-line scan, CollectorStage already handled URLs
    }
    // ... existing rule + entropy scan
}
```

**CLI flag:**
```go
scanCmd.Flags().IntVar(&maxScanLineLen, "max-scan-line-len", 100000, "skip per-line scanning on lines exceeding this length (0=unlimited)")
```

**Relation to `--max-file-size` and `--js-beautify`:**
- `--max-file-size` skips large files entirely (file-level gate)
- `--js-beautify` splits minified content into shorter lines (structural fix)
- `--max-scan-line-len` is the safety net for any remaining long lines (performance guard)

## Files Changed

| File | Change |
|------|--------|
| `internal/entropy/entropy.go` | Add `IsMediaToken()` with magic byte detection |
| `internal/entropy/entropy_test.go` | Tests for `IsMediaToken()` |
| `internal/scanner/scanner.go` | Add `MaxScanLineLen` to Config |
| `internal/scanner/scan.go` | Gate line loop on `MaxScanLineLen`; wire `IsMediaToken` in entropy path |
| `cmd/scan.go` | Add `--max-scan-line-len` flag |
| — | `base64.StdEncoding` from stdlib covers decode |

## Open Questions

1. Should `MaxScanLineLen` apply to both rule matching AND entropy scanning, or only entropy? **Design decision:** apply to both — if a line is too long for regex, it's too long for entropy regex too.
2. Should we log a debug message when skipping a long line? **Yes** — with rate-limiting: log only first N (e.g., 10) per file to avoid flood on single-file bundles with thousands of long lines.
3. Media token filter: should we also check for embedded font data (WOFF/WOFF2, TTF, OTF)? **Yes** — include WOFF and TTF magic numbers.

## Future Work (Not in Scope)

- File entropy filter: skip files where >90% of bytes are base64 alphabet (binary content)
- Context-aware filter: if file is `swagger-ui-bundle.min.js` and finding is in a line that looks like a library, auto-downgrade
- Vendor path detection: skip `.min.js` in known CDN paths
- FP fingerprinting: mark specific token+path combinations as ignored
