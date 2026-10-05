# SYCK Phased Hardening — Design Spec (Batch 1)

Date: 2026-10-05
Path chosen: A phased hardening (Batch 1 first)
Status: awaiting user review before implementation plan

## 1. Intent

Owner resuming side project `syck` (Go secret scanner + recon engine).
Goal: fix verified audit findings in shippable batches without breaking
CLI contracts, then continue feature work on a clean baseline.

Success for Batch 1: exploitable holes closed, CI unblocked, all tests
green with `-race`, no new pipeline stages.

## 2. Phase breakdown (approved)

- Batch 1 (this spec): security correctness + CI unblock.
- Batch 2: detection quality (unreachable decoders, context gating,
  prefix FPs, dedup, confidence scale unification).
- Batch 3: performance/stability (per-line goroutines, rate-limiter lock,
  buffers, SQLite WAL, `-w 0` clamp, crawl-limit TOCTOU).
- Batch 4: refactor/health (split `scan.go`/`cmd/scan.go`, unify
  endpoint detection, V1/V6 doc, missing tests for
  config/gitscan/json_scanner).

## 3. Batch 1 scope (approved)

In scope:
- `internal/validator/http.go:18,22` TLS verify on.
- `internal/scanner/helpers.go:12-20` same-origin-only cred forward.
- SSRF guard for sitemap child fetch
  (`internal/crawler/sitemap.go:156-166`), sourcemap fetch
  (`internal/scanner/helpers.go:373-388`), redirect follow
  (`internal/crawler/crawler.go:117-123`,
  `internal/httpclient/client.go:90-95`).
- `internal/formatters/webhook.go:33-69` honor `--redact`, HTTPS default.
- `internal/finding/finding.go:44-49` case-insensitive severity parse.
  Fixes 9 lowercase rules in `internal/rules/builtin.yaml:898-953`
  reporting as LOW.
- `internal/crawler/crawler.go:346-375` single mutex for `visited` map.
- Gzip/archive caps (`internal/decoder/pipeline.go:176-195`,
  `internal/scanner/scan.go:270`).
- `gofmt -w` 14 dirty files; fix `cmd/root.go:19` +
  `cmd/env.go:15` env binding (`SYCK_<CMD>_<FLAG>` for all subcommands,
  surface `Set` errors); reconcile version (`main.go:6` 1.1.0 vs docs
  1.2.0) and rule count (202 actual vs 210+ claimed).

Out of scope: decoder reachability, dedup redesign, perf pool rewrites,
file splits, new providers/rules. No V1/V6 pipeline changes.

Behavior changes (intentional): TLS verified for `--validate`; no
cross-origin `Authorization`/cookie forward; SSRF denies logged and
skipped; severity labels correct LOW to actual; plain-HTTP webhook
requires explicit opt-in.

## 4. Component changes (approved)

- `httpclient`: validator constructs client with
  `insecureSkipVerify=false`; add `NewValidatorClient` wrapper to
  prevent drift.
- `scanner/headerTransport`: compare redirect request host vs original;
  forward creds only on same host (including port-agnostic host match).
- New `internal/netguard` helper `AllowFetch(url) bool` denying 10/8,
  172.16/12, 192.168/16, 169.254/16, link-local, and
  `metadata.google.internal` / `metadata.google.internal.`; wired into
  sitemap, sourcemap, and `CheckRedirect`.
- `formatters/webhook`: apply existing `RedactSecret` pre-pass when
  `--redact`; refuse `http://` webhook URL unless
  `--allow-insecure-webhook` is set.
- `finding.ParseSeverity`: `strings.ToUpper` input before map lookup.
- `crawler`: single mutex guarding `visited` + queue ops with documented
  lock order; verified by `-race`.
- `decoder`: gzip/zlib bounded `io.LimitReader` (5 MB); `scanner`
  archive path `Stat` size gate before `os.ReadFile`.
- `cmd`: iterate `rootCmd.Commands()` in `PersistentPreRunE` binding;
  correct prefix derivation; warn on bad env values; `gofmt -w`;
  version bump + doc count fix.

## 5. Data flow, errors, testing (approved)

Flow: scan input to `AllowFetch` gate on every secondary fetch to
findings to corrected severity to redact pre-pass to output.
No new stages.

Errors: denies and over-cap skips log under `--debug` and skip the item;
invalid `SYCK_*` warns to stderr; no silent proxy bypass changes in
Batch 1 beyond surfacing errors.

Testing gates: `go build`, `gofmt -l .` empty, `go vet ./...` clean,
`go test -race ./...` green. New unit tests: severity case-fold,
redirect same/cross-origin, netguard deny/allow table, webhook redact.
`ruletest` corpus unchanged in Batch 1.

## 6. Risks

- Severity relabel raises visible HIGH/CRITICAL counts (correct but may
  trip existing `--fail-on` CI gates). Mitigate via CHANGELOG note.
- SSRF deny may break intentional intranet scans. Mitigate with
  `--allow-private-ips` escape hatch (default off).
- Env binding fix may newly honor previously-ignored `SYCK_SCAN_*`
  values. Mitigate by documenting precedence: flags override env.
