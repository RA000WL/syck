# SYCK Batch 3 Performance & Stability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove lock-across-sleep, silent SQLite lock failures, unbounded memory growth, and per-line goroutine churn — with byte-identical findings.

**Architecture:** 3a fixes concurrency primitives (rate limiter, worker clamp, SQLite pragmas), 3b bounds memory (streaming buffers, response reads, archive slicing), 3c improves throughput and is benchmark-gated. Independent sub-batches; 3c lands last.

**Tech Stack:** Go 1.26+, modernc.org/sqlite, existing `internal/crawler` + `internal/scanner` patterns.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch3-performance-design.md`

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- **No finding-visible behavior change.** Same findings, same order, same exit codes. Rules, decoders, dedup, confidence, and formatters are untouched by Batch 3.
- `--rate-limit N` must remain **per host**; a fix must not make it global.
- Streaming path still handles minified mega-lines via the existing `bufio.ErrTooLong` → `scanFileFallback` path.
- `SetMaxOpenConns(1)` on SQLite is intentional (single writer); must be paired with a busy timeout.
- 3c's regex change ships only if a benchmark proves it is not slower.
- Every task ends green: `go build`, `gofmt -l .` empty for touched files, `go vet`, `go test -race`, `ruletest` 40/40.

## Review Focus

- `--rate-limit 5` across 3 hosts: expect roughly 5 req/sec per host concurrently, not 5 total — Task 1 test pins overlap.
- `--workers 0` via the library API (not CLI): expect the walk to complete, not hang — Task 2 test pins with a timeout guard.
- Concurrent `RecordFileMtime` from N workers: expect no `database is locked` and no silent miss — Task 3 test pins.
- A 2MB single-line file: expect it to still be scanned (via fallback), not truncated or dropped — Task 4 test pins.
- A 150MB `.zip`: expect a clean skip or partial scan, never a corrupt-archive error from a mid-directory slice — Task 5 test pins.

---

### Task 1: Rate limiter sleeps outside the lock

**Files:**
- Modify: `internal/crawler/crawler.go:54-65` (`hostRateLimiter.Wait`)
- Test: `internal/crawler/ratelimit_test.go` (create; check `ls internal/crawler/*_test.go` first)

**Interfaces:**
- Consumes: `newHostRateLimiter(rps int) *hostRateLimiter` (unchanged)
- Produces: same signatures. `Wait(host string)` sleeps without holding `h.mu`.

- [ ] **Step 1: Write the failing test**

```go
func TestRateLimiterAllowsPerHostOverlap(t *testing.T) {
    // rps=5 => minGap=200ms. Spawn 3 goroutines waiting on 3 DIFFERENT hosts simultaneously.
    // Assert total elapsed < 200ms*2 (i.e. they overlapped) while a single-host
    // double-wait still respects the gap.
}
```

Use a generous margin (e.g. assert elapsed < 350ms for the 3-host case, which must take ~200ms serially but ~200ms overlapped; and assert the single-host repeat takes >= 200ms) so the test is not timing-flaky. Keep `-race` clean.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/crawler/ -run TestRateLimiterAllowsPerHostOverlap -v`
Expected: FAIL (3 hosts serialize to ~600ms because `h.mu` is held across the sleep)

- [ ] **Step 3: Implement** — read `lastTime[host]` under the lock, release the lock, sleep if needed, re-acquire to write `lastTime[host] = time.Now()`. Keep per-host semantics: different hosts never block each other; the same host still respects `minGap`. Note the small race window (two goroutines on the same host could both sleep) is acceptable and bounded by `minGap`; state it in a code comment.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/crawler/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/crawler/crawler.go internal/crawler/ratelimit_test.go
git commit -m "perf(crawler): sleep outside rate-limiter lock"
```

---
### Task 2: Workers clamp inside the scanner

**Files:**
- Create: `internal/scanner/workers.go` — `func effectiveWorkers(n int) int` returning `n` when positive, else `max(runtime.NumCPU(), 2)`
- Modify: `internal/scanner/scan.go:63` (`sem = make(chan struct{}, cfg.Workers)` → `effectiveWorkers(cfg.Workers)`)
- Modify: `cmd/scan.go:781-788` — replace `clampWorkers` body with a call to the scanner's helper (export it as `scanner.EffectiveWorkers` so one definition serves both) OR keep `cmd` as-is and note the duplication in the commit body if `cmd` cannot import it cleanly (it can — `cmd` already imports `internal/scanner`)
- Test: `internal/scanner/workers_test.go` (create)

**Interfaces:**
- Produces: `func EffectiveWorkers(n int) int` exported from `internal/scanner`; `cmd.clampWorkers` becomes a thin wrapper `return scanner.EffectiveWorkers(n)` (keeps the `cmd` name so the Batch 1 test `TestWorkersClamp` keeps passing)

- [ ] **Step 1: Write the failing tests**

```go
func TestEffectiveWorkers(t *testing.T) {
    if EffectiveWorkers(7) != 7 { t.Fatal("positive passthrough") }
    if got := EffectiveWorkers(0); got < 2 { t.Fatalf("zero must clamp >=2, got %d", got) }
    if got := EffectiveWorkers(-3); got < 2 { t.Fatalf("negative must clamp >=2, got %d", got) }
}
func TestScanPathsZeroWorkersDoesNotHang(t *testing.T) {
    // t.Parallel not needed. Build a tiny temp dir with 2 files, Config{Workers: 0, Rules: rs}.
    // Run ScanPaths in a goroutine; assert it returns within 10s (fail rather than hang the suite).
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run 'TestEffectiveWorkers|TestScanPathsZeroWorkers' -v -timeout 60s`
Expected: FAIL (symbol missing; and with the test in place, `ScanPaths` with `Workers: 0` deadlocks — the timeout guard is what converts the hang into a failure)

- [ ] **Step 3: Implement** — add `internal/scanner/workers.go`; use it at the semaphore construction; delegate `cmd.clampWorkers`.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ ./cmd/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/workers.go internal/scanner/workers_test.go internal/scanner/scan.go cmd/scan.go
git commit -m "fix(scanner): clamp workers internally, share helper with cmd"
```

---
### Task 3: SQLite concurrency hardening

**Files:**
- Modify: `internal/correlator/cache.go:17-21` (`OpenCache`) and `:234-236` (`RecordFileMtime` returns error)
- Modify: `internal/crawler/urlcache.go:15-19` (`OpenURLCache`)
- Modify: all `RecordFileMtime` call sites (`internal/scanner/scan.go` ×2 sites) — handle/aggregate the new error under `cfg.Debug`
- Test: `internal/correlator/cache_test.go` (extend if present) + a concurrency test

**Interfaces:**
- Produces: `func (c *Cache) RecordFileMtime(path string, mtime int64) error` (signature change — update every caller, `grep -rn RecordFileMtime`); both openers apply `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`, `db.SetMaxOpenConns(1)`

- [ ] **Step 1: Write the failing tests**

```go
func TestOpenCacheAppliesPragmas(t *testing.T) {
    // open a temp cache; query PRAGMA journal_mode => expect "wal";
    // PRAGMA busy_timeout => expect 5000; db.Stats().MaxOpenConnections => expect 1
}
func TestConcurrentRecordFileMtime(t *testing.T) {
    // 8 goroutines x 50 INSERT OR REPLACE on distinct paths; assert zero errors, no "database is locked"
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -race ./internal/correlator/ -run 'TestOpenCacheAppliesPragmas|TestConcurrentRecordFileMtime' -v`
Expected: FAIL (journal_mode is "delete", MaxOpenConnections 0/unlimited)

- [ ] **Step 3: Implement** the pragmas + single-writer cap + error return; update all callers (log under `cfg.Debug`, never abort the scan).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/correlator/ ./internal/crawler/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/correlator/cache.go internal/crawler/urlcache.go internal/correlator/cache_test.go internal/scanner/scan.go
git commit -m "fix(sqlite): WAL + busy timeout + single writer; surface mtime errors"
```

---
### Task 4: Bounded streaming + pooled ScanReader buffer

**Files:**
- Modify: `internal/scanner/scan.go:29-34` (`streamingBufPool` 10MB → 256KB) and `:978` (`ScanReader` uses the pool instead of `make([]byte, 10<<20)`)
- Test: `internal/scanner/streaming_test.go` (extend if present)

**Interfaces:**
- Consumes: nothing new
- Produces: same signatures. Mega-line handling still routes through `scanFileFallback` on `bufio.ErrTooLong`.

- [ ] **Step 1: Write the failing tests**

```go
func TestStreamingPoolBufferSize(t *testing.T) {
    // assert the pooled buffer capacity is 256KB (or <= 256KB)
}
func TestMegaLineStillScanned(t *testing.T) {
    // 2MB single-line file containing a rule-matching secret; ScanFile must still report the finding
    // (via scanFileFallback) — this is the regression guard for the smaller buffer
}
func TestScanReaderReusesPooledBuffer(t *testing.T) {
    // benchmark or allocation check: calling ScanReader twice must not allocate a 10MB buffer each time;
    // use testing.AllocsPerRun or a Benchmark with -benchmem and assert B/op is far below 10MB
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -run 'TestStreamingPool|TestMegaLine|TestScanReaderReuses' -v`
Expected: FAIL on buffer size and allocation assertions

- [ ] **Step 3: Implement** the two edits. Keep the `bufio.ErrTooLong` fallback intact — do not remove or reorder it.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ -v && go test ./internal/scanner/ -run XXX -bench BenchmarkScanReader -benchmem 2>/dev/null | tail -5` (add the benchmark if absent)
Expected: PASS; allocation figure far below 10MB

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/scan.go internal/scanner/streaming_test.go
git commit -m "perf(scanner): 256KB streaming pool, pooled ScanReader buffer"
```

---
### Task 5: fetchURL bounded read + archive skip-not-slice

**Files:**
- Modify: `internal/crawler/crawler.go` `fetchURL` (~445-470) — replace the manual grow loop with `io.LimitReader(resp.Body, 10MB+1)` + `io.ReadAll`; return pooled scratch only, drop the `string(utf8Body)` intermediate duplication where cheap
- Modify: `internal/crawler/archive.go:39-41` (`scanZip` truncation) and the tar equivalents (~78-90) — return an error/skip instead of slicing mid-archive
- Test: `internal/crawler/fetch_test.go` (create) + extend existing archive tests

**Interfaces:**
- Consumes: `crawler.BodyPool` (64KB scratch, `internal/crawler/encoding.go:14`)
- Produces: `fetchURL(client *http.Client, rawURL string, customUA string) (string, string, error)` — same signature; hard cap stays 10MB

- [ ] **Step 1: Write the failing tests**

```go
func TestFetchURLTruncatesAtCap(t *testing.T) {
    // httptest server streaming >10MB; assert returned content <= 10MB and no error
}
func TestScanZipOversizeSkipsNotSlices(t *testing.T) {
    // build a zip whose stored bytes exceed maxArchiveTotalBytes (or a >100MB synthetic buffer);
    // assert ScanArchive returns a clean error/skip rather than a zip central-directory error
}
```

For the second test, constructing a real >100MB zip is expensive — prefer asserting the guard directly: if `len(data) > maxArchiveTotalBytes`, `scanZip` must not attempt `zip.NewReader` on the truncated slice (assert the returned error mentions size/skip, not "zip: not a valid zip file"). Document that choice in the test comment.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/crawler/ -run 'TestFetchURLTruncates|TestScanZipOversize' -v`
Expected: FAIL (loop overshoots the cap; oversize zip produces a corrupt-archive error)

- [ ] **Step 3: Implement** both edits.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/crawler/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/crawler/crawler.go internal/crawler/archive.go internal/crawler/fetch_test.go
git commit -m "perf(crawler): bounded body reads, skip oversize archives"
```

---
### Task 6: Benchmark-gated regex path + atomic crawl budget + scoped .js.map

**Files:**
- Modify: `internal/scanner/helpers.go:478-511` (`scanLineForRegexRules`) — benchmark FIRST (below), then drop the per-line goroutine branch only if faster
- Modify: `internal/crawler/crawler.go:186,328,342` — replace the three `visitedCount() < cfg.Limit` checks with one atomic budget (`CompareAndSwap`) on a `budget` field
- Modify: `internal/crawler/crawler.go:328-338` (`.js.map` enqueue) — route through the same scope/domain filters as normal links
- Test: `internal/scanner/bench_test.go` (exists? add if not) + `internal/crawler/crawl_limit_test.go` (create)

**Interfaces:**
- Consumes: Tasks 1-2 (crawler + scanner changes)
- Produces: `crawler.budget` atomic field; same public APIs

- [ ] **Step 1: Write the benchmark and the crawl tests**

```go
func BenchmarkScanLineForRegexRules(b *testing.B) {
    // realistic line set from a fixture file; b.ReportAllocs()
}
func TestCrawlLimitNotOvershot(t *testing.T) {
    // httptest server linking to many pages; Concurrency 10; assert len(results) <= Limit under -race
}
func TestJsMapRespectsScope(t *testing.T) {
    // server serving /app.js with a sourceMappingURL, Scope regexp excluding .map;
    // assert the .map URL is never crawled
}
```

- [ ] **Step 2: Run the crawl tests to verify they fail**

Run: `go test -race ./internal/crawler/ -run 'TestCrawlLimitNotOvershot|TestJsMapRespectsScope' -v`
Expected: `TestJsMapRespectsScope` FAIL (bypasses scope today)

- [ ] **Step 3: Benchmark the current regex path and record the baseline**

Run: `go test ./internal/scanner/ -run XXX -bench BenchmarkScanLineForRegexRules -benchmem -count=5 | tee /tmp/opencode/3c-baseline.txt`
Expected: a recorded ns/op + allocs/op baseline (this is the decision input, not a pass/fail)

- [ ] **Step 4: Implement the sequential path, then re-benchmark**

Change `scanLineForRegexRules` to call `scanLineForRegexRulesChunk` for all rules directly (no goroutines). Re-run Step 3's command.
**Decision rule (controller-ruled):** keep the sequential version only if its median ns/op is <= the baseline median; otherwise REVERT the regex change and ship only the crawl-budget + scope fixes in this task. Record the numbers in the commit body either way.

- [ ] **Step 5: Run tests and gates**

Run: `go test -race ./internal/crawler/ ./internal/scanner/ -v && go run . ruletest 2>&1 | tail -1`
Expected: PASS, `40 tested, 40 PASSED`

- [ ] **Step 6: Commit**

```bash
git add internal/scanner/helpers.go internal/scanner/bench_test.go internal/crawler/crawler.go internal/crawler/crawl_limit_test.go
git commit -m "perf: atomic crawl budget, scoped .js.map, benchmark-gated regex path"
```