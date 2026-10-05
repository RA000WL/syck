# SYCK Batch 1 Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close verified Batch 1 security correctness holes and unblock CI without changing the scan pipeline.

**Architecture:** Small surgical fixes behind existing interfaces plus one new `internal/netguard` gate package; new CLI escape-hatch flags default off; TDD with failing test first per task.

**Tech Stack:** Go 1.26+, cobra/pflag, Go regexp (RE2), net/http, modernc.org/sqlite (untouched), `go test -race`.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch1-hardening-design.md`

## Global Constraints

- Go 1.26+; module `github.com/RA000WL/syck`.
- No new pipeline stages; V1/V6 orchestration untouched.
- `--allow-private-ips` default off; `--allow-insecure-webhook` default off.
- Gzip/zlib decode cap 5 MB; archive direct-file `Stat` size gate before `os.ReadFile`.
- Every task ends green: `go build`, `gofmt -l .` empty for touched files, `go vet` on touched packages, targeted `go test -race`.
- Flags override env; env parse errors warn to stderr, never silent-fail the scan.

## Review Focus

- Intranet scan with `--allow-private-ips` unset hitting `http://192.168.1.1/admin` as a sitemap child: expect skip + debug log, no fetch.
- Cross-origin redirect `https://target.com -> https://attacker.example/` with `--auth-token`: expect no `Authorization` header on second request.
- Webhook to `http://hooks.example/x` without opt-in: expect refusal error, zero POST.
- Lowercase `severity: critical` rule file: expect CRITICAL finding, not LOW.
- `-w 0` and 200 MB `.zip` direct arg: expect clamp to sane workers and size-gate skip, no hang or OOM.

---
### Task 1: Case-insensitive severity parse

**Files:**
- Modify: `internal/finding/finding.go:44-49`
- Test: `internal/finding/finding_test.go` (create if missing; check existing test files first with `ls internal/finding/`)
- Verify data: `internal/rules/builtin.yaml:898-953` (9 lowercase severities, read-only)

**Interfaces:**
- Consumes: `SeverityFromName map[string]Severity`
- Produces: `ParseSeverity(s string) Severity` — case-insensitive, unknown still returns `SeverityLow`

- [ ] **Step 1: Write the failing test** in `internal/finding/finding_test.go`:

```go
func TestParseSeverityCaseInsensitive(t *testing.T) {
    if ParseSeverity("critical") != SeverityCritical { t.Fatal("lowercase critical") }
    if ParseSeverity("High") != SeverityHigh { t.Fatal("mixed high") }
    if ParseSeverity("MEDIUM") != SeverityMedium { t.Fatal("upper medium") }
    if ParseSeverity("bogus") != SeverityLow { t.Fatal("unknown fallback") }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/finding/ -run TestParseSeverityCaseInsensitive -v`
Expected: FAIL on lowercase critical

- [ ] **Step 3: Implement `ParseSeverity` in `internal/finding/finding.go`** using `strings.ToUpper(s)` before map lookup (`strings` already imported).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/finding/ ./internal/rules/ -v`
Expected: PASS; confirm the 9 lowercase rules now load as HIGH/MEDIUM/CRITICAL via `go run . list-rules 2>&1 | grep -i env_aws_secret` or equivalent rule-list command

- [ ] **Step 5: Commit**

```bash
git add internal/finding/finding.go internal/finding/finding_test.go
git commit -m "fix(finding): case-insensitive ParseSeverity"
```

---
### Task 2: Validator TLS verification on

**Files:**
- Modify: `internal/validator/http.go:16-23`, `internal/httpclient/client.go` (add wrapper only, keep `NewClient` signature)
- Test: `internal/validator/validator_test.go` (append new test)

**Interfaces:**
- Consumes: `httpclient.NewClient(timeout time.Duration, proxyURL string, insecureSkipVerify bool) *http.Client`
- Produces: `InitValidatorClient(proxyURL string)` — builds with `insecureSkipVerify=false`; `init()` same; new `NewValidatorClient(timeout time.Duration, proxyURL string) *http.Client` wrapper in `internal/httpclient` (single place that pins verify-on for validators)

- [ ] **Step 1: Write the failing test** in `internal/validator/validator_test.go`:

```go
func TestValidatorTLSVerifyEnabled(t *testing.T) {
    InitValidatorClient("")
    tr, ok := httpClient.Transport.(*http.Transport)
    if !ok { t.Fatal("not *http.Transport") }
    if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
        t.Fatal("validator must verify TLS")
    }
}
```

(Check imports in `validator_test.go` first; add `net/http` import if missing.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/validator/ -run TestValidatorTLSVerifyEnabled -v`
Expected: FAIL with "must verify TLS"

- [ ] **Step 3: Implement** — change both `NewClient(..., true)` calls in `internal/validator/http.go` to `false`; add `NewValidatorClient(timeout, proxyURL)` wrapper in `internal/httpclient/client.go` that calls `NewTransport(proxyURL, false)`; use it from validator. Remove the `// #nosec G402` justification or move it only to an explicit opt-in path if one exists.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/validator/ ./internal/httpclient/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/validator/http.go internal/validator/validator_test.go internal/httpclient/client.go
git commit -m "fix(validator): enable TLS verification"
```

---
### Task 3: Same-origin-only credential forwarding

**Files:**
- Modify: `internal/scanner/header_transport.go:12-20`
- Test: `internal/scanner/header_transport_test.go` (extend; read existing tests first)

**Interfaces:**
- Consumes: `headerTransport{base http.RoundTripper, headers map[string][]string}`
- Produces: `RoundTrip(req *http.Request)` — forwards injected headers only when redirect target host matches the original request host (compare `req.URL.Hostname()` vs `via[0].URL.Hostname()`; Go passes redirect chain via `req.Response` — simplest correct approach: wrap `http.Client.CheckRedirect` in `buildHTTPClient` to strip on cross-host OR track origin host in transport; chosen approach must be stated in the task's first commit message)

- [ ] **Step 1: Write the failing test** — cross-host redirect must drop `Authorization` and `Cookie`, same-host must keep:

```go
func TestHeaderTransportCrossOriginStrip(t *testing.T) {
    // build transport with Authorization: Bearer x, RoundTrip a request
    // whose Response.Request.URL host differs; assert dropped.
}
```

(Read `header_transport_test.go:1-60` first and match its harness style; test both same-host keep and cross-host strip.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scanner/ -run TestHeaderTransport -v`
Expected: FAIL on cross-host case

- [ ] **Step 3: Implement** in `internal/scanner/header_transport.go` — on cross-hostname requests, do not add `Authorization`, `Cookie`, `X-Api-Key` (case-insensitive); forward all other custom headers unchanged. Port differences do not strip (hostname comparison only).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/scanner/ -run TestHeaderTransport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/header_transport.go internal/scanner/header_transport_test.go
git commit -m "fix(scanner): same-origin-only credential forwarding"
```

---
### Task 4: SSRF netguard gate

**Files:**
- Create: `internal/netguard/netguard.go`
- Create test: `internal/netguard/netguard_test.go`
- Modify: `internal/crawler/sitemap.go:122-166` (gate `fetchAndParse` child URLs), `internal/scanner/helpers.go:373-388` (gate sourcemap fetch), `internal/httpclient/client.go:90-95` + `internal/crawler/crawler.go:112-124` (gate `CheckRedirect`), `cmd/scan.go` (add `--allow-private-ips` flag, plumb through `scanner.Config` → crawl/sitemap paths)

**Interfaces:**
- Consumes: raw URL strings
- Produces: `func AllowFetch(rawURL string) bool` — false for 10/8, 172.16/12, 192.168/16, 169.254/16, link-local, `metadata.google.internal` (with and without trailing dot); true otherwise (DNS hostnames allowed; literal IP check only, no DNS resolution in Batch 1)

**Files note:** check `internal/scanner/scanner.go:17` `Config` struct first; add `AllowPrivateIPs bool` field there.

- [ ] **Step 1: Write the failing test** in `internal/netguard/netguard_test.go`:

```go
func TestAllowFetchDenyTable(t *testing.T) {
    deny := []string{"http://10.0.0.1/", "http://172.16.5.4:8080/x", "http://192.168.1.1/admin", "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/"}
    for _, u := range deny { if AllowFetch(u) { t.Fatalf("should deny %s", u) } }
    allow := []string{"https://example.com/", "https://8.8.8.8/"}
    for _, u := range allow { if !AllowFetch(u) { t.Fatalf("should allow %s", u) } }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/netguard/ -v`
Expected: FAIL (package missing)

- [ ] **Step 3: Implement `AllowFetch`** in `internal/netguard/netguard.go` with `net.ParseIP` + CIDR checks and hostname denylist; wire gates: sitemap child fetch skip + debug log, sourcemap fetch skip + debug log, `CheckRedirect` return error on denied target (stops redirect). Honor `AllowPrivateIPs` escape hatch at call sites (skip gate when true).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/netguard/ ./internal/crawler/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/netguard/ internal/crawler/sitemap.go internal/scanner/helpers.go internal/httpclient/client.go internal/crawler/crawler.go internal/scanner/scanner.go cmd/scan.go
git commit -m "feat(netguard): SSRF guard for secondary fetches"
```

---
### Task 5: Webhook redact + HTTPS default

**Files:**
- Modify: `internal/formatters/webhook.go:33-69`, `internal/formatters/formatter.go` (reuse `RedactSecret` helper)
- Modify: `cmd/scan.go:113-114,188-189,720-729` (add `--allow-insecure-webhook` flag, pass redact + allow flag into `PostWebhook`)
- Test: append to existing webhook/formatter test file (check `ls internal/formatters/*_test.go` first)

**Interfaces:**
- Consumes: `[]finding.Finding`, existing `RedactSecret(secret string) string`
- Produces: `PostWebhook(url string, style WebhookStyle, findings []finding.Finding, opts ...WebhookOption)` — refuses `http://` URLs with error unless allow-insecure set; redacts secrets in slack/discord/json payloads when redact=true

- [ ] **Step 1: Write the failing test**:

```go
func TestPostWebhookRefusesPlainHTTP(t *testing.T) {
    err := PostWebhook("http://127.0.0.1:1/x", WebhookJSON, nil)
    if err == nil { t.Fatal("expected refusal") }
}
func TestSlackPayloadRedacts(t *testing.T) {
    // build one finding with Secret "AKIAIOSFODNN7EXAMPLE", redacted payload must not contain full secret
}
```

(Check `PostWebhook` signature first — if `WebhookOption` has no redact/allow fields yet, define `WithRedact(bool)` and `WithAllowInsecure(bool)` in this task.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/formatters/ -run 'TestPostWebhook|TestSlackPayload' -v`
Expected: FAIL

- [ ] **Step 3: Implement** — add options, gate `http` scheme, apply `RedactSecret` to `Secret` fields in all three payload builders when redact=true.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/formatters/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/formatters/webhook.go cmd/scan.go internal/formatters/*_test.go
git commit -m "fix(webhook): honor redact, refuse plain HTTP by default"
```

---
### Task 6: Bounded gzip/archive reads

**Files:**
- Modify: `internal/decoder/pipeline.go:176-195` (`TryGzipDecompress`), `internal/scanner/scan.go:258-289` (archive `os.ReadFile` path)
- Test: `internal/decoder/pipeline_test.go` (append; read existing first)

**Interfaces:**
- Consumes: raw bytes
- Produces: same signatures; `TryGzipDecompress` caps output at 5 MB via `io.LimitReader`; archive path stats file first and skips with debug log when over `cfg.MaxFileSize`

- [ ] **Step 1: Write the failing test**:

```go
func TestTryGzipDecompressCapsOutput(t *testing.T) {
    // highly-compressible >5MB payload gzipped; assert len(out) <= 5<<20 and ok==true
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/decoder/ -run TestTryGzipDecompressCapsOutput -v`
Expected: FAIL (output exceeds cap)

- [ ] **Step 3: Implement** — `io.LimitReader(r, 5<<20+1)` + truncate; archive branch: `os.Stat` first, skip when `size > cfg.MaxFileSize` with `[debug]` log.

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/decoder/ ./internal/scanner/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/decoder/pipeline.go internal/scanner/scan.go internal/decoder/pipeline_test.go
git commit -m "fix(decoder): bound gzip and archive reads"
```

---
### Task 7: Crawler visited-map race fix

**Files:**
- Modify: `internal/crawler/crawler.go:74-89,343-397`
- Test: existing crawler tests with `-race` plus a new concurrency test in `internal/crawler/crawler_test.go` (check existing file first)

**Interfaces:**
- Consumes: `crawler` struct fields `visited`, `queue`, `results`
- Produces: single-mutex discipline — all `visited` access under one mutex (`mu`), documented lock order `queueMu -> mu` or merged; no behavior change to BFS order

- [ ] **Step 1: Write the failing test**:

```go
func TestCrawlConcurrentVisitedRace(t *testing.T) {
    cfg := CrawlConfig{Limit: 20, MaxDepth: 1, Concurrency: 10, HostConcurrency: 2}
    // seed with mix of duplicate URLs against local httptest server; run Crawl; assert no panic and deduped results
}
```

(Use `httptest.NewServer`; keep it hermetic, no external network.)

- [ ] **Step 2: Run test to verify it fails or races**

Run: `go test -race ./internal/crawler/ -run TestCrawlConcurrentVisitedRace -v`
Expected: FAIL or `WARNING: DATA RACE` on current code

- [ ] **Step 3: Implement** — route `nextURL`, `markVisited`, `visitedCount`, `enqueueURLs`, and the `.js.map` block (`crawler.go:318-328`) through one mutex; remove dual-lock `visited` access; keep `markVisited(entry.url)` call harmless (idempotent under single mutex).

- [ ] **Step 4: Run tests to verify**

Run: `go test -race ./internal/crawler/ -v`
Expected: PASS, no race warnings

- [ ] **Step 5: Commit**

```bash
git add internal/crawler/crawler.go internal/crawler/crawler_test.go
git commit -m "fix(crawler): single-mutex visited map"
```

---
### Task 8: Hygiene — env binding, workers clamp, gofmt, version

**Files:**
- Modify: `cmd/env.go:11-22`, `cmd/root.go:18-21`, `cmd/scan.go:211-212,442-443` (workers clamp), `main.go:6` (version), `README.md` + `ARCHITECTURE.md` (rule count 202, version 1.2.0)
- Test: `cmd/env_test.go` (extend; read first)

**Interfaces:**
- Consumes: cobra commands + `os.LookupEnv`
- Produces: `bindEnvToFlags` binds every subcommand's flags with `SYCK_<CMD>_<FLAG>` prefix and warns to stderr on bad values instead of `_ =` ignore; `workers <= 0` clamps to `runtime.NumCPU()` (min 10? use `max(NumCPU, 2)` — state exact choice in commit message)

- [ ] **Step 1: Write the failing test** — first pin actual behavior:

```go
func TestBindEnvScanFlags(t *testing.T) {
    // set SYCK_SCAN_WORKERS=7, bind scanCmd, assert workers flag == 7; unset afterwards
}
```

If this passes on current code (runScan binds scanCmd directly), keep the test as the pin and fix only the root prefix (`SYCK_SYCK_*` → bind each subcommand) + surface `Set` errors.

```go
func TestWorkersClamp(t *testing.T) {
    if got := clampWorkers(0); got <= 0 { t.Fatalf("workers 0 must clamp positive, got %d", got) }
    if got := clampWorkers(-3); got <= 0 { t.Fatalf("negative workers must clamp positive, got %d", got) }
}
```

(If no `clampWorkers` helper exists yet, create it in `cmd/scan.go` and use it when building `scanCfg.Workers`.)

- [ ] **Step 2: Run test to record behavior**

Run: `go test ./cmd/ -run TestBindEnv -v`
Expected: documents pass or fail; implement to make scan binding + error surfacing pass

- [ ] **Step 3: Implement** — iterate `rootCmd.Commands()` in `PersistentPreRunE` (or bind the invoking `cmd` in `runScan`, keeping one path); `fmt.Fprintf(os.Stderr, ...)` on `Set` error; clamp `workers`; `gofmt -w` the 14 dirty files; bump version; fix rule counts in docs.

- [ ] **Step 4: Run verification**

Run: `gofmt -l . ; go vet ./... ; go test -race ./cmd/ ./internal/scanner/ -v`
Expected: `gofmt -l` empty, vet clean, tests PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/ main.go README.md ARCHITECTURE.md
git commit -m "fix(cli): env binding, workers clamp, gofmt, version drift"
```

---
### Task 9: Full Batch 1 gates

**Files:** none (verification only)

- [ ] **Step 1: Run full gates**

Run: `go build -o /tmp/opencode/syck-batch1 . && gofmt -l . && go vet ./... && go test -race ./...`
Expected: build OK, `gofmt -l` empty output, vet clean, all packages PASS (30 ok, 4 no-test as baseline)

- [ ] **Step 2: Run rule-quality gate**

Run: `go run . ruletest 2>&1 | tail -20`
Expected: documents precision/recall delta from severity relabel (env rules now HIGH/CRITICAL); no crash

- [ ] **Step 3: Commit nothing** — if gates fail, file follow-up tasks; do not fold new fixes into this plan.
