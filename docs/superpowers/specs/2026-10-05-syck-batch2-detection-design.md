# SYCK Batch 2 Detection Quality — Design Spec

Date: 2026-10-05
Path chosen: A pipeline order (2a decoders → 2b rules → 2c dedup/confidence)
Status: awaiting user review before implementation plan

## 1. Intent

Follow Batch 1 (hardening + CI unblock, merged on local main) with
detection quality: find more real secrets, emit fewer false positives,
and stop corrupting triage signal in post-processing. Each sub-batch
ships green independently.

Success: `ruletest` corpus grows with touched rules and stays green;
decoder coverage goes from 4/9 to 9/9 reachable; dedup preserves
actionable findings.

## 2. Sub-batch scopes (approved)

### 2a — Decoder reachability (this spec's implementation target)

- Wire all 9 decoders to `scanner.Config` + CLI flags. New flags
  (default off): `--decode-base64url`, `--decode-jwt`,
  `--decode-double-base64`, `--decode-charcode`.
- Fix `scanDecodedChunk` 500-char truncation
  (`internal/decoder/pipeline.go:118-120`): scan the full chunk.
- Fix `tryHex` mixed-case drop (`internal/decoder/decoders.go:57`).
- Fix JWT padding order (`internal/decoder/jwt.go:24-25`): pad, then
  try `URLEncoding` before `RawURLEncoding`.
- Bound recursion fan-out with a per-line visited-set of
  already-scanned texts.
- Collapse `registry.go` vs `decoders.go:activeDecoders` dual
  selection into the single `PrecomputeDecoders` path.
- Fix `ScanReader` hardcoding `hasDecoders=false`
  (`internal/scanner/scan.go:958`) so `--decode-*` works on `--pipe`.

Out of scope for 2a: any rule regex change, any dedup/confidence
change, any formatter change.

### 2b — Rule FP/FN (future spec + plan)

- FP: `requires_context` on `sk_`/short-prefix cluster
  (`elevenlabs_api_key`, `mapbox_api_token`, `moonshot`, `runway`,
  `dropbox`, `airtable`, `asana`), `basic_auth_header`,
  `credential_url`; gate `terraform_state_secret` and
  `kubernetes_kubeconfig_token`; context-gate or demote
  `email_address`.
- FN: add OpenAI legacy `sk-`, AWS bare 40-char secret, GitLab
  `gldt-/glft-/glodt-/glimt-`, Slack `xoxp/xoxa/xoxo/xoxr/xoxs`,
  plus `SendGrid`/Mailchimp refresh; remove exact-dup
  `discord_webhook`; reconcile ~15 overlapping rules.
- Update `ruletest` corpus for every touched rule; precision must
  not regress.

### 2c — Dedup + confidence (future spec + plan)

- Fix `DeduplicateBySecret` (`internal/finding/finding.go:148-188`):
  preserve line info, keep rule attribution correlator- and
  adaptive-compatible (no comma-joined names breaking exact-match
  lookups in `correlation/helpers.go` and adaptive weights).
- Unify dual confidence scales (`finding` consts vs
  `internal/confidence/confidence.go` vs hardcoded scan paths).
- Refresh stale `highCertaintyRules` names in
  `internal/adaptive/adaptive.go:120` against current
  `builtin.yaml`.
- Extend ruletest harness past regex-only where cheap
  (context gates, FP filters, dedup).

## 3. 2a component changes (approved)

- `decoder`: `Flags` + `PrecomputeDecoders` cover all 9 decoders;
  single selection path; full-chunk scan; mixed-case hex; JWT
  encode order; per-line visited-set.
- `scanner`: `Config` gains `DecodeBase64URL`, `DecodeJWT`,
  `DecodeDoubleBase64`, `DecodeCharCode`; wired into `scanContent`,
  streaming (`scanFileStreaming`), and `ScanReader`.
- `cmd/scan.go`: 4 new `--decode-*` flags, default off;
  `SYCK_SCAN_*` env binding applies via the Batch 1 path.
- Tests: per-decoder table tests, fan-out bound test (nested input
  finishes, finding count sane), config-plumbing test (flag on →
  decoded finding appears).

## 4. Data flow, errors, testing (approved)

Flow: line → existing 4 decoders (defaults unchanged) → newly-enabled
decoders append findings through the same `scanDecoded` path →
existing dedup/FP filters untouched. No formatter, correlator, or
confidence changes in 2a.

Errors: undecodable input stays silent-skip; Batch 1's 5 MB gzip cap
still applies; visited-set is per-line, memory flat.

Testing gates: `go build`, `gofmt -l .` empty,
`go test -race ./internal/decoder/ ./internal/scanner/`,
`ruletest` stays 30/30 (any delta investigated, not
baseline-updated — corpus updates belong to 2b).

## 5. Risks

- New decoders default off, so output volume is unchanged until
  opt-in; flipping defaults later is a separate decision with its
  own FP review (belongs to 2b measurement, not 2a).
- Removing the 500-char truncation increases per-line scan work on
  decoded blobs; bounded by the existing 1024-char chunking plus
  the new visited-set.
- Collapsing the dual decoder-selection path may break any caller
  using `registry.NewRegistry` directly — the implementation plan
  must check call sites first and keep a shim if one exists.
