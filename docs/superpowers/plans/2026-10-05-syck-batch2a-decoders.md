# SYCK Batch 2a Decoder Reachability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make all 9 decoders reachable via config/flags and fix known decoder correctness bugs, with default output unchanged.

**Architecture:** Fix decoder primitives first (order/truncation/fan-out), then plumb 4 new bools through `scanner.Config` into every `decoder.Flags` construction site, then expose 4 CLI flags (default off) and fix the stdin path. TDD throughout.

**Tech Stack:** Go 1.26+, Go stdlib `encoding/base64`, `encoding/hex`, existing `decoder` package patterns.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch2-detection-design.md` (section 2a)

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- 4 new flags default off: `--decode-base64url`, `--decode-jwt`, `--decode-double-base64`, `--decode-charcode`. Default scan output must be byte-identical to pre-change.
- CharCode derivation preserved: `CharCode: cfg.DecodeCharCode || cfg.DecodeHex || cfg.DecodeUnicode`.
- Batch 1's 5 MB gzip cap still applies; visited-set is per-line (memory flat).
- `ruletest` stays 30/30 — any delta is investigated, never baseline-updated (corpus updates belong to 2b).
- Every task ends green: `go build`, `gofmt -l .` empty for touched files, `go vet` on touched packages, targeted `go test -race`.

## Review Focus

- Mixed-case hex now decodes, so camelCase words matching the hex regex may newly produce findings: expect `ruletest` green plus the Task 1 natural-word test to pin no-fire on non-hex text.
- Base64 and double-base64 both on over the same line: expect no crash or explosion, findings bounded — Task 2 fan-out test pins it.
- JWT without `exp` or with odd padding: expect no regression in decode behavior — Task 1 padded/unpadded tests pin it (`ScanExpiredJWTs` path itself untouched).
- Default flags off: expect byte-identical findings vs pre-change on a fixture — Task 3 defaults-off test pins it.
- `--decode-hex` alone: expect charcode still active via preserved derivation — Task 3 derivation test pins it.

---

### Task 1: Hex + JWT decode-order fixes

**Files:**
- Modify: `internal/decoder/decoders.go:51-75` (remove `hasMixedCase` skip; keep `hasMixedCase` func only if another caller exists, else delete it)
- Modify: `internal/decoder/jwt.go:20-30` (try padded `URLEncoding` first, fallback `RawURLEncoding` on unpadded)
- Modify: `internal/decoder/base64url.go:20-29` (same order fix — identical defect shape to tryJWT; spec names jwt.go, this extends the same one-line pattern)
- Test: `internal/decoder/decoders_test.go`, `internal/decoder/jwt_test.go` (check existing files first with `ls internal/decoder/*_test.go`; append or create)

**Interfaces:**
- Consumes: nothing new
- Produces: unchanged signatures `tryHex`, `tryJWT`, `tryBase64URL` — behavior only. `IsJWTExpired` (`jwt.go:40-63`) intentionally untouched (fail-closed `false` on undecodable is conservative; out of spec).

- [ ] **Step 1: Write the failing tests**

```go
func TestTryHexMixedCase(t *testing.T) {
    // real mixed-case hex of "AKIA..."-style ASCII: hex.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE")) has A-F + a-f mix
    line := "token=" + hex.EncodeToString([]byte("AKIAIOSFODNN7EXAMPLE"))
    if len(tryHex(line)) == 0 { t.Fatal("mixed-case hex should decode") }
}
func TestTryHexNaturalWordNoFire(t *testing.T) {
    if len(tryHex("the beefcake face feeds deadbeef hunger")) != 0 { t.Fatal("natural words must not decode") }
}
func TestTryJWTPaddedPayload(t *testing.T) {
    // payload len%4 != 0 requiring "=" padding, exp far future
    if len(tryJWT("x."+base64PayloadNeedingPad+".sig eyJ...")) == 0 { t.Fatal("padded JWT should decode") }
}
```

(Construct the JWT test with a real padded payload: `base64.URLEncoding.EncodeToString([]byte(...))` containing `{"sub":"123"}`; assert decoded text contains `sub`. Also keep an unpadded-payload case asserting decode works.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/decoder/ -run 'TestTryHex|TestTryJWT' -v`
Expected: FAIL on mixed-case and padded-JWT cases (natural-word passes already — it pins no-regression)

- [ ] **Step 3: Implement** — remove `hasMixedCase` skip in `tryHex` (delete func if unreferenced); reorder decode attempts in `tryJWT` and `tryBase64URL` to padded-first.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/decoder/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/decoder/decoders.go internal/decoder/jwt.go internal/decoder/base64url.go internal/decoder/*_test.go
git commit -m "fix(decoder): mixed-case hex, JWT/base64url decode order"
```

---

### Task 2: Truncation removal + recursion fan-out bound

**Files:**
- Modify: `internal/decoder/pipeline.go:59-81` (`recursiveDecode` carries `visited map[string]bool` of scanned texts, skip repeats), `internal/decoder/pipeline.go:109-120` (remove 500-char truncation; scan full chunk)
- Modify: `internal/decoder/decoders.go:166-168` (route `activeDecoders` through `PrecomputeDecoders`; delete `activeDecoders` — verified only caller is `DecodeAndRescan` at `pipeline.go:31`, plus no external callers per grep)
- Test: `internal/decoder/pipeline_test.go` (append; read existing first)

**Interfaces:**
- Consumes: `PrecomputeDecoders(flags Flags) []Decoder`
- Produces: unchanged `DecodeAndRescan` / `DecodeAndRescanWithDecoders` signatures; per-line visited-set is internal to `recursiveDecode`

- [ ] **Step 1: Write the failing tests**

```go
func TestDecodedScanSeesLateSecret(t *testing.T) {
    // AWS-style secret placed at offset >500 inside base64-decoded blob; assert finding found
}
func TestRecursiveDecodeFanoutBound(t *testing.T) {
    // doubly-base64-nested input with base64+doublebase64 decoders; assert returns promptly with sane count (<50 findings)
}
```

(Build inputs programmatically: `base64.StdEncoding.EncodeToString` of padding + secret at offset 600; nested `EncodeToString(EncodeToString(secret))`. Need a `*rules.RuleSet` — check how `pipeline_test.go` / `bench_test.go` construct one and follow that pattern.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/decoder/ -run 'TestDecodedScanSeesLateSecret|TestRecursiveDecodeFanoutBound' -v`
Expected: FAIL (truncation misses late secret; fan-out likely still passes count — it pins the bound going forward)

- [ ] **Step 3: Implement** — drop truncation (scan `decodedText` as-is; chunking at `scanDecoded` already bounds work); add `visited` map threaded through `recursiveDecode` (mark text before scanning, skip if seen); replace `activeDecoders` body with `PrecomputeDecoders` call then delete the function and update its one caller.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/decoder/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/decoder/pipeline.go internal/decoder/decoders.go internal/decoder/pipeline_test.go
git commit -m "fix(decoder): drop 500-char truncation, bound recursion fan-out"
```

---

### Task 3: Config + Flags plumbing for 4 new decoders

**Files:**
- Modify: `internal/scanner/scanner.go:28-32` (add `DecodeBase64URL`, `DecodeJWT`, `DecodeDoubleBase64`, `DecodeCharCode bool` after `DecodeGzip`)
- Modify: `internal/scanner/scan.go` — all `decoder.Flags{...}` construction sites (`scanContent` ~825, `scanFileStreaming` ~546) plus `hasDecoders` bools (~111, ~251, ~282, ~304) to include the 4 new fields; `CharCode: cfg.DecodeCharCode || cfg.DecodeHex || cfg.DecodeUnicode`
- Modify: `internal/scanner/stage_decoder.go:9-25` (extend V1 `DecoderFlags` with the 4 fields + Gzip, pass through — keeps unused-by-CLI V1 path consistent)
- Test: `internal/scanner/decoder_flags_test.go` (create; hermetic, no network)

**Interfaces:**
- Consumes: `decoder.Flags` (all 9 fields), `decoder.PrecomputeDecoders`
- Produces: `scanner.Config` with 4 new fields; `scanContent`/`scanFileStreaming` honor them

- [ ] **Step 1: Write the failing tests**

```go
func TestNewDecodersDefaultOff(t *testing.T) {
    // zero Config (all decode false) over fixture with base64url + fromCharCode + JWT content: expect zero decoded findings
}
func TestNewDecodersOptIn(t *testing.T) {
    // Config{DecodeBase64URL: true, ...} over same fixture via ScanContent: expect base64url_/jwt_/charcode_/doublebase64_-tagged findings
}
func TestCharCodeDerivationPreserved(t *testing.T) {
    // Config{DecodeHex: true} over String.fromCharCode fixture: expect charcode finding without explicit DecodeCharCode
}
```

(Fixture: craft inputs with a rule-matching secret, e.g. `AKIA...` behind each encoding; check `rules.LoadDefault` usage in scanner tests for RuleSet construction. Tag assertions: `strings.HasPrefix(f.RuleName, "base64url_")` etc.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run 'TestNewDecoders|TestCharCodeDerivation' -v`
Expected: FAIL (fields/flags don't exist → build failure counts as RED; record it)

- [ ] **Step 3: Implement** — add Config fields, extend every `decoder.Flags{...}` literal and `hasDecoders` bool, extend V1 `DecoderFlags`.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ ./internal/decoder/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scan.go internal/scanner/stage_decoder.go internal/scanner/decoder_flags_test.go
git commit -m "feat(scanner): plumb 4 new decoder flags through Config"
```

---

### Task 4: CLI flags + stdin fix + gates

**Files:**
- Modify: `cmd/scan.go` — 4 flag vars, 4 `Flags().BoolVar` registrations (default false, help text `"<codec> decode lines and rescan"` matching existing style), 4 `scanCfg` wirings
- Modify: `internal/scanner/scan.go:936-958` (`ScanReader`: compute `hasDecoders` from cfg like `scanContent` instead of hardcoded `false`; build `df`/`activeDec` the same way)
- Test: extend `cmd` tests if a scan-flag test file exists (check `ls cmd/*_test.go`), else verify via new test asserting flag defaults false; plus a `ScanReader`-with-decoders case in `internal/scanner` (stdin path: pipe base64 content with `DecodeBase64: true`, expect finding)

**Interfaces:**
- Consumes: `scanner.Config` 4 new fields from Task 3
- Produces: `--decode-base64url`, `--decode-jwt`, `--decode-double-base64`, `--decode-charcode` (default off, `SYCK_SCAN_*` env binding automatic via Batch 1 path)

- [ ] **Step 1: Write the failing tests** — flag-default assertions + `ScanReader` decoder test (both fail pre-implementation: unknown flags / hardcoded false).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/ ./internal/scanner/ -run 'TestDecode|TestScanReader' -v`
Expected: FAIL

- [ ] **Step 3: Implement** flags, wiring, and `ScanReader` fix.

- [ ] **Step 4: Run verification**

Run: `go build -o /tmp/opencode/syck-2a . && gofmt -l . && go vet ./internal/decoder/ ./internal/scanner/ ./cmd/ && go test -race ./internal/decoder/ ./internal/scanner/ ./cmd/`
Expected: build OK, gofmt empty, vet clean, all PASS

- [ ] **Step 5: Run rule-quality gate**

Run: `go run . ruletest 2>&1 | tail -3`
Expected: `Summary: 30 tested, 30 PASSED` — any delta vs Batch 1 baseline is investigated as a bug, never accepted silently

- [ ] **Step 6: Commit**

```bash
git add cmd/scan.go internal/scanner/scan.go cmd/*_test.go internal/scanner/*_test.go
git commit -m "feat(cli): 4 new decode flags, stdin decoder fix"
```
