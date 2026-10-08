# SYCK Batch 11 — fetchURL Scratch Pooling — Design Spec

Date: 2026-10-08
Status: grounded; one function, benchmark-gated

## 1. Intent

`internal/crawler/crawler.go`'s `fetchURL` allocates a fresh grow-by-doubling buffer per fetch:

```go
body, err := io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))
```

Every crawled URL allocates up to 10MB, and `ConvertToUTF8` + `string(utf8Body)` allocate again on top. The Batch 3 spec listed "returns pooled scratch" as approved-and-completed work; only the bounded-read half shipped. `crawler.BodyPool` was the orphan hook, deleted in Batch 4d as dead code, and the gap is recorded in `ARCHITECTURE.md` §15 item 5.

## 2. Shape

`fetchURL` has exactly one production caller (`crawler.go:377`) and one test caller (`fetch_test.go:23`), and returns `(string, string, error)` — the body as a string.

Pool the byte slice:

```go
buf := pool.Get().(*[]byte)
buf = buf[:0]
defer pool.Put(buf)          // AFTER the string copy, never before
body, err := io.ReadAll(io.LimitReader(reader, maxBodyBytes+1))
// ... copy to string, then return
```

**The `Put` must follow the copy.** `io.ReadAll` may return a slice that the caller keeps by aliasing, and `string(buf)` is the copy boundary. Putting before copying is a use-after-free class bug that `-race` does not reliably catch — §15 item 5 says so explicitly.

Cap the returned buffer: do not `Put` a slice that grew to 10MB back into the pool, or one oversized entry pins the pool for the rest of the crawl.

## 3. Acceptance

**Benchmark-gated, not assertion-gated.** The point is allocation reduction, so:

- add a benchmark for `fetchURL` against an `httptest` server
- measure before and after, report `allocs/op` and `B/op`
- **if the pooled version is not better, revert and report that.** §15 item 5 requires a benchmark before this change ships. A pooling change that does not reduce allocations is churn with a use-after-free risk attached.

## 4. Testing

- Existing `fetch_test.go` must pass unmodified — it already exercises the success and error paths.
- Add a test that the pooled buffer is not aliased: fetch twice through the same client and assert the first result's string is unchanged after the second fetch. This is the test that catches a premature `Put`.
- Add a test for the oversize path (a body larger than the cap) — already covered by existing behavioural expectations, but confirm the pool does not retain an oversized buffer.

## 5. Risks

- **Premature `Put`** — use-after-free, not reliably caught by `-race`. The aliasing test is the only guard.
- **Pool retention** — one 10MB buffer pinned across the crawl defeats the purpose. Cap on return.
- `sync.Pool` under `-race` — a data race here would be a real bug, not a test artefact.
- This is a memory change, so correctness gates (`ruletest`, parity) say nothing. Do not cite them as evidence the pooling works.
