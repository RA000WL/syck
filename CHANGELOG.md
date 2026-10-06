# Changelog

All notable changes to syck are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — Batch 3: performance

### Fixed

- Rate limiter no longer sleeps while holding its mutex (crawler and
  parambrute). Previously `time.Sleep` ran under the lock, so one host's
  wait forced every other host to queue — capping the limiter at a global
  N req/s. A latent bug in the crawler (single call site) but live in
  parambrute, whose N fetch workers genuinely contend: `--rate-limit`
  silently collapsed to a global rate there.
- `--workers` is now clamped inside the scanner, so library callers can
  no longer deadlock or panic on 0/negative values.

### Changed

- SQLite caches now use WAL mode + a 5s busy timeout + a single writer
  connection; cache-write errors are reported under `--debug` instead of
  silently dropped.
  **WAL caveat:** SQLite creates `-wal` and `-shm` sidecar files next to
  `--cache-db` / `--url-cache-db`. Copying or moving only the `.db` file
  without its sidecars can lose pending findings/verdicts/mtimes — copy
  the whole set together, or close the scan first.
- Streaming scan buffers reduced 10MB → 256KB per worker (~100MB → ~2.5MB
  at the default concurrency). `ScanReader` (stdin) keeps a 10MB one-shot
  buffer, so large minified-JS lines on stdin still scan without falling
  back or truncating.
- Response bodies are read through a bounded reader; oversized archives
  are skipped with a clear error instead of being truncated mid-directory.
- Crawl limit is enforced via an atomic budget so `--crawl-limit` cannot
  overshoot; auto-harvested `.js.map` URLs now respect scope.

### Benchmarks

- The per-line goroutine regex fan-out was benchmarked against a sequential
  alternative and **kept**: sequential measured ~31% slower (median
  235291 vs 179737 ns/op) despite allocating 2 vs 29 allocs/op.

## [2.0.0] — Batch 2: detection quality

Two prior batches landed before this release: Batch 1 (security hardening + CI
unblock) is listed under [1.2.0](#120--batch-1-security-hardening) below.

### Breaking / behavior changes

- **Findings counts increase in one case.** Cross-rule dedup now keeps one
  finding per *occurrence* instead of collapsing every occurrence of a secret
  in a file into a single finding at the first line. When one secret matches
  several rules in the same file, you now get several findings. This restores
  line-level triage signal; multi-rule attribution moved to a new `RuleNames`
  field while `RuleName` stays a single exact rule name (required by
  correlation detectors and adaptive weights).
- **Confidence band values change.** Confidence is now unified on a single
  0–120 scale (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`), replacing the two
  competing scales. Expect findings to land in different bands than before.

### Added

- Decoder reachability: `base64url`, `jwt`, `double-base64`, and `charcode`
  decoders were implemented but unreachable from config or CLI. Four new flags
  wire them up, all **default off** so existing output is unchanged:
  `--decode-base64url`, `--decode-jwt`, `--decode-double-base64`,
  `--decode-charcode`.
- Two new detection rules: `openai_legacy_key` (legacy `sk-…` OpenAI keys) and
  `slack_user_token` (`xoxp-…`).
- Per-rule entropy thresholds are now enforced in the regex scan paths. The
  `entropy_threshold` field was parsed but never applied outside a single rule.
- `--pipe` (stdin) scans now honor every `--decode-*` flag. They were silently
  ignored on that path.

### Fixed

- Decoded scans truncated decoded text at 500 characters, hiding any secret
  past that offset.
- Recursive decoding could fan out exponentially on nested encodings; bounded
  per-line with a visited set.
- Mixed-case hex input was dropped instead of decoded.
- JWT and base64url payloads were decoded before padding was attempted, so
  padded payloads failed to decode.
- 6 short-prefix rules fired on ordinary text (length minimums and context
  gating added): `elevenlabs_api_key`, `mapbox_api_token`, `moonshot_api_key`,
  `runway_api_key`, `dropbox_api_token`, `airtable_api_key`.
- 10 generic-shape rules produced false positives on ordinary content and are
  now context-gated, including `email_address`, `basic_auth_header`,
  `credential_url`, and `elasticsearch_cloud_id`.
- `oracle_cloud_ocid` only matched redacted `...` placeholders, never real IDs.
- 5 subsumed duplicate rules removed (`discord_webhook`,
  `postgres_connection_url`, `mysql_connection_url`, `mongodb_connection_string`,
  `gitlab_runner_registration_token`); each survivor matches a superset. Rule
  count: 202 → 199.
- 9 lowercase `severity:` values in the rule file normalized to uppercase.
- The adaptive engine's high-certainty rule list named no real rules, so its
  −10 penalty cap for high-precision providers never applied.
- Per-rule entropy thresholds now apply to decoded (base64/hex/…) content as
  well as plaintext.
- The default `--format text` output no longer re-collapses per-secret
  findings: it renders one line per occurrence with `file:line`, matching the
  count `--format json` reports for the same scan. Sibling rule names are now
  surfaced in every output format (JSON, JSONL, CSV, SARIF, Markdown, HTML);
  SARIF carries them as rule properties rather than inventing top-level keys.
- `--diff` now marks every occurrence of a newly-recorded secret as new.
  Previously only the first occurrence was flagged, because later ones hit
  the fingerprint's uniqueness constraint and were recorded as updates.
- A finding's `Confidence`, `ConfidenceBand`, and `DetectionMethod` now come
  from the same rule that `RuleName` names. They could previously be
  inherited from a different rule matching the same secret at the same
  offset, yielding a severity that disagreed with its own confidence band.

## [1.2.0] — Batch 1: security hardening

- Validator TLS verification is enabled. Live secret validation previously
  skipped certificate verification, exposing the secrets being validated to
  interception.
- Auth headers (`Authorization`, `Cookie`, `X-Api-Key`) are no longer
  forwarded across cross-origin redirects; same-host redirects still receive
  them.
- New SSRF gate (`internal/netguard`) covers sitemap child and leaf URLs,
  source-map fetches, and redirect targets. Denies private ranges, loopback,
  link-local, and cloud metadata addresses. Escape hatch:
  `--allow-private-ips`.
- Webhook export honors `--redact`, and refuses plaintext `http://` endpoints
  unless `--allow-insecure-webhook` is set.
- Gzip/zlib decompression and archive reads are bounded; oversized archives are
  skipped instead of read into memory.
- Fixed a data race on the crawler's visited-URL map (two mutexes guarded one
  map), plus a permanent regression test.
- `SYCK_SCAN_*` environment variables now bind correctly. Explicit CLI flags
  take precedence over environment variables.
- `-w 0` (and negative worker counts) no longer hang a scan.
- Repository-wide `gofmt` compliance; version and rule-count drift corrected.

[2.0.0]: https://github.com/RA000WL/syck/releases/tag/v2.0.0
[1.2.0]: https://github.com/RA000WL/syck/releases/tag/v1.2.0