# SYCK Batch 3 Performance & Stability — Design Spec

Date: 2026-10-05
Status: awaiting user review before implementation plan

## 1. Intent

Follow Batch 1 (hardening) and Batch 2 (detection quality) with
performance and stability. All findings below were re-verified against
current HEAD (post-2c, 33 local commits) before this spec was written.

Success: identical findings and output; measurable resource wins; no
locks held across sleeps; no unbounded memory; no silent SQLite lock
failures. `ruletest` stays 40/40, `-race` suite stays green.

## 2. Sub-batch scopes (approved)

### 3a — Concurrency and locks

- `hostRateLimiter.Wait` (`internal/crawler/crawler.go:54-65`) holds
  `h.mu` across `time.Sleep`, serializing every host against a
  per-host limit. Release the lock before sleeping.
- `ScanPaths` (`internal/scanner/scan.go:63`) builds
  `sem = make(chan struct{}, cfg.Workers)`. `Workers == 0` (or
  negative) deadlocks the walk for library callers; only `cmd` clamps
  today (`cmd/scan.go:clampWorkers`). Clamp inside the scanner using
  one shared helper so CLI and library agree.
- `correlator.OpenCache` and `crawler.OpenURLCache` set no SQLite
  pragmas and no connection limit, so concurrent scan/crawl writes can
  fail with `database is locked`, silently degrading the cache.
  Apply WAL journal mode, a busy timeout, and a single-writer
  connection cap.
- `RecordFileMtime` swallows errors; surface them.

### 3b — Memory

- Streaming buffers are 10MB each, pooled per worker
  (`internal/scanner/scan.go:30-34`) — roughly 100MB at the default 10
  workers, ~1GB at `--workers 100`.
- `ScanReader` allocates a fresh 10MB buffer per call instead of
  reusing the pool (`scan.go:978`).
- `fetchURL` grows a local buffer that is never returned to
  `BodyPool`, checks the 10MB cap only after reading, and doubles
  memory via `string(utf8Body)` (`crawler.go:445-470`).
- `crawler/archive.go` truncates with `data[:100MB]`, slicing mid-zip
  and corrupting the central directory instead of skipping.

### 3c — Throughput (lands last, benchmark-gated)

- `scanLineForRegexRules` (`internal/scanner/helpers.go:486`) spawns
  `NumCPU` goroutines and a WaitGroup for every line whenever the
  rule count is >= 64. With 199 rules that is every line. Drop the
  per-line goroutine path only if a benchmark shows sequential
  chunked matching is not slower.
- Crawl budget is checked non-atomically in three places
  (`crawler.go:186,328,342`), so `--crawl-limit` can overshoot.
- `.js.map` auto-enqueue bypasses scope and domain filtering.

Out of scope for Batch 3: rule content, decoders, dedup, confidence,
formatters, and any finding-visible behavior change.

## 3. Component changes (approved)

- **3a:** rate limiter sleeps outside the lock; scanner clamps
  `Workers` internally with the shared clamp helper; both SQLite
  openers apply `PRAGMA journal_mode=WAL`, a busy timeout, and
  `SetMaxOpenConns(1)`; `RecordFileMtime` returns an error.
- **3b:** streaming buffer pool reduced (still well above realistic
  line lengths; the `bufio.ErrTooLong` → `scanFileFallback` path
  already covers minified mega-lines); `ScanReader` reuses the pool;
  `fetchURL` reads through a bounded `io.LimitReader` and returns
  pooled scratch; archive oversize skips rather than slices.
- **3c:** sequential chunked regex matching if the benchmark agrees;
  one atomic crawl budget via `CompareAndSwap`; `.js.map` enqueue
  routed through the normal scope and domain filters.

## 4. Data flow, errors, testing (approved)

Findings, ordering, and exit codes are unchanged — only goroutine,
buffer, and database mechanics differ. Crawl URL selection is
equivalent (the budget cap is preserved; ordering was already
nondeterministic under concurrency).

Errors: SQLite lock contention reports a real error instead of a
silent cache miss; archive oversize skips with a `[debug]` log,
consistent with the Batch 1 gate; the rate limiter must keep
per-host semantics — `--rate-limit 5` must not become 5/sec globally.

Testing:
- 3a: concurrent `Wait` across N hosts proving overlap; `Workers: 0`
  walk completes (timeout-guarded); concurrent `RecordFileMtime`
  under `-race`.
- 3b: allocation/RSS assertion on a synthetic large file; pool reuse
  confirmed by a benchmark delta.
- 3c: before/after benchmark on a 100k-line fixture (keep the change
  only if wall-clock improves); crawl test asserting
  `len(results) <= Limit` under concurrency with scope still applied.

Gates per task: `go test -race ./...`, `ruletest 40/40`, `gofmt`,
`go vet`. Batch 3 ships no changelog entry except a brief performance
note (including the WAL sidecar-file caveat).

## 5. Risks

- Reducing the streaming buffer changes which files take the streaming
  path at all; a regression here shows up as slower scans on minified
  JS, not as wrong output. The 3b benchmark guards it.
- `SetMaxOpenConns(1)` serializes SQLite writes. That is the intended
  trade (correctness over write parallelism) but must be paired with a
  busy timeout so concurrent readers do not fail fast.
- Sequential regex matching could be slower on multi-core machines
  with large rule sets. This is exactly why 3c is benchmark-gated and
  lands last.
- WAL mode creates `-wal`/`-shm` sidecar files next to user cache DBs.
  Acceptable; noted in the changelog performance entry.