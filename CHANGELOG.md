# Changelog

All notable changes to syck are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — Batch 6: security fixes (**adds findings**) + Batch 4c: shared internal-URL predicates (**breaking**) + Batch 3: performance + Batch 5: entropy-floor consistency + Batch 7: dedup-key truncation fix (**adds findings**)

This section carries five batches, so the title names them and flags the two
that change visible output. **Read the Batch 6 entry first if you are diffing
finding counts between versions: it makes syck report findings it previously
stayed silent about, so finding counts go UP.** Batch 6 is listed first for
that reason and is not breaking in the API sense. Batch 4c **changes** recon's
internal-surface output, including a class of input that no longer produces a
High-severity finding. Batch 3 (performance work) is not breaking. Batch 5 is a
detection-consistency fix that **removes** findings on two paths; it is not
breaking and touches no public API. Batch 7, like Batch 6, makes finding
counts go **UP**: distinct secrets that share a long prefix used to be merged
into a single finding (see its entry under "### Fixed" below).

### Changed

- Recon's internal-surface detection (`classifyInternal`) now delegates to the
  shared `internal/internalurl` predicates instead of ten local regexes. Six
  of the seven categories move; `container_service` keeps its local regex
  because the `docker|container` + `host|name|id|service` vocabulary appears
  nowhere else in the codebase. The branch **order is unchanged** and is a
  precedence chain — `internal` → `internal_host` → `private_ip` → `localhost`
  → `cloud_metadata` → `container_service` → `sensitive_port`.

  Seven behavior deltas, all in `classifyInternal`'s categories:

  | Input | Was | Now | Direction |
  |---|---|---|---|
  | `http://LOCALHOST/api` | `""` | `localhost` | widening — adds a Low finding |
  | `http://127.1.2.3/x` | `""` | `localhost` | widening — adds a Low finding |
  | `http://[::1]/x` | `""` | `localhost` | widening — adds a Low finding |
  | `http://[::]/x` | `""` | `localhost` | widening — adds a Low finding |
  | `http://foo.com/10.0.0.1/x` | `private_ip` | `""` | narrowing — **removes a Medium finding** |
  | `http://foo.com/169.254.169.254/x` | `cloud_metadata` | `""` | narrowing — **removes a High finding** |
  | `http://example.com/localhost` | `localhost` | `""` | narrowing — **removes a Low finding** |

  **Three of the seven remove findings, one of them a High.** That is the cost
  of the delegation and it is stated here rather than buried: a private IP, the
  metadata address, or the loopback name appearing anywhere other than the host
  no longer produces a finding. Three further narrowings are not separate
  classes but the same mechanism in positions the table does not name — a
  query or fragment instead of a path, a hostname that embeds an IP literal
  (`127.0.0.1.nip.io`, `10.0.0.1.example.com`, `localhost.example.com`, all of
  which the old text regexes matched *inside the host*), and userinfo
  (`http://10.0.0.1@evil.com/x` was `private_ip`, now `""`, because `hostOf`
  takes the part after the last `@`, which is the real host `evil.com`). None of
  these forms are swept, since they are not in the generator's token vocabulary.

  **One of those lost signals has no compensating control, and an earlier draft
  of this entry wrongly claimed otherwise.** `127.0.0.1.nip.io` resolves to
  loopback, so it is a real internal surface, but it is now classified as an
  ordinary public host and **`netguard` does not catch it either**:
  `netguard.AllowFetch("http://127.0.0.1.nip.io/")` returns `true`. `netguard`
  performs literal-IP checks only — its own package doc says "Batch 1 performs
  literal-IP checks only: no DNS resolution" — and `netguard_test.go` pins
  `AllowFetch("http://localhost/") == true`. Nothing in the codebase resolves a
  name before deciding to fetch it.

  A real mitigation would require a gate that resolves the hostname and checks
  the returned addresses, which is exactly the resolution Batch 1 deliberately
  does not perform. That is a separate, security-relevant change with its own
  risk profile (TOCTOU on the answer, DNS rebinding, latency per fetch) and is
  **not** delivered by this batch. Until it exists, treat "a DNS name that
  resolves to a private address is not detected" as a known gap, not a covered
  case.

  **Loopback detection is now correct for IPv6, for all of 127/8, and for the
  case-insensitive name.** The old regex hardcoded
  `localhost|127\.0\.0\.\d+|0\.0\.0\.0` and carried no `(?i)` flag, so `[::1]`,
  `::1`, `::`, `127.1.2.3` and `http://LOCALHOST/api` all matched nothing.
  `internalurl.IsLoopback` parses the host and uses `ip.IsLoopback()` (covering
  `127/8` and `::1`) plus `ip.IsUnspecified()` (covering `0.0.0.0` and `::`), and
  compares the lowercased host against the name `localhost` — a URI `host`
  component is case-insensitive per RFC 3986 §3.2.2, and RFC 4343 §2 states the
  same for host names. These four widenings only ever **add** Low-severity
  findings.

  **All three narrowings share one cause, and it is deliberate — do not restore
  the old text match.** The shared predicates parse the URL's host, which is
  what lets them call `netguard`'s CIDR list instead of keeping a second,
  independently editable copy of the RFC 1918 ranges, the metadata address, and
  the loopback set. The same raw-text-to-host-parse switch is why a private IP,
  `169.254.169.254`, or the loopback tokens stopped classifying when they are not
  the host: a private IP in a path is a different signal from a private-IP
  host — the host there is `foo.com`, a public name — and the same argument
  applies to the metadata address and the loopback name. A bare `10.0.0.1`,
  `localhost` or `169.254.169.254` with no scheme is unaffected, because
  `hostOf` falls back to the lowercased input, so it still classifies.

  Reinstating a text match for these three cases would re-duplicate the CIDR
  list that `internalurl` exists to centralize — the exact duplication this
  batch removed. If a future input class genuinely needs a path-scoped IP
  match, add a separate, explicitly-named check rather than reverting this one.

  **Scope of the evidence.** `internal/recon/detector_internal_delta_test.go`
  ships the old regexes, the delta ledger, and a generator that sweeps every
  token the deleted regexes could match — the RFC 1918 ranges and their
  boundaries, the loopback tokens and their neighbours, the metadata address
  and hostname, plus public and internal-host controls — across five scheme
  forms, every position a URL can place text (authority, path, query,
  fragment, and a scheme-lookalike inside a path or query), and interesting
  hosts crossed with interesting paths. Over that generated cross-product no
  transition appears outside the mechanisms above. That is a statement about
  **this generator's token vocabulary, not about the input space**: a
  transition needing a token outside the vocabulary would not be found. The
  generator also asserts that each declared mechanism is still exercised, so
  trimming the vocabulary cannot quietly reduce the claim.

  - `internalurl`'s host extractor no longer mistakes a `://` inside a URL's path,
  query, or fragment for a scheme. It previously stripped a scheme by taking the
  first `://` anywhere in the string, so a scheme-less URL whose query carried an
  absolute URL had its host read out of that query:
  `localhost?u=http://169.254.169.254/` yielded the host
  `169.254.169.254`. Through the delegated predicates that turned a loopback URL
  into a **High**-severity cloud-metadata finding driven purely by
  attacker-supplied query text — a false escalation. `hostOf` now strips a scheme
  only when the `://` appears before the first `/`, `?`, or `#`; a later one
  belongs to that component. Genuine schemes still strip, so
  `http://10.0.0.1/x` is still a `private_ip` host.

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

### Fixed

- **Batch 5 — a rule's own `entropy_threshold` is now honored on the
  reconstructed-JavaScript and JSON paths.** This is a **consistency** fix:
  the same input used to produce a finding on these two paths and silence on
  the main file-scanning path, and now all three apply the same floor.

  `internal/jsrecon/reconstruct.go:416` (reconstructed JavaScript) and
  `internal/json_scanner/scanner.go:111` (JSON values) each gated every rule
  match on a hardcoded global `e < 2.0`. Both now call
  `decoder.RuleEntropyFloor(rule.EntropyThreshold)` — the helper the plain-file
  path has used since an earlier batch (`internal/scanner/helpers.go:555` and
  `internal/scanner/scan_stream.go:101`, unchanged here). The floor is the
  same everywhere now; only the two lagging call sites moved.

  `env_generic_secret` is the **only** rule in the ruleset carrying an
  `entropy_threshold` (`grep -c entropy_threshold internal/rules/builtin.yaml`
  → `1`, value 3.0), so it is the only rule whose behavior can change. For
  every other rule `RuleEntropyFloor(0)` returns 2.0 — the value that was
  hardcoded — and behavior is byte-for-byte unchanged.

  | Input | Span entropy | Before (these 2 paths) | After |
  |---|---|---|---|
  | `MY_SECRET=aaaaaaaa` | 2.7250 | reported | suppressed |
  | `DB_PASSWORD=hunter2hunter2` | 4.0080 | reported | reported |

  Verified end to end with built binaries at `4b8ea10` (pre-fix) and at this
  commit. A reconstructed-JS span at entropy 2.2890 drops from 1 finding to 0;
  the JSON path drops from 2 findings to 1 (`json_env_generic_secret` goes
  away; a *different*, higher-entropy reconstruction of the same input is
  unaffected). Both high-entropy fixtures keep their finding on every path.

  Three gates were deliberately **left alone**, and `ARCHITECTURE.md` §15 now
  records them:

  - `internal/json_scanner/scanner.go:75` keeps a literal `e >= 3.0`. That is
    the secret-key-**name** heuristic, not a rule match — it fires on
    `secretKeyRE.MatchString(keyName)` with no `rule` in scope, so there is no
    threshold to read and no way to spell 3.0 via the helper. It is now pinned
    by `TestJSONKeyNameHeuristicFloorIsExactlyThreeNotRuleEntropyFloor` so a
    future "consistency" pass cannot quietly rewrite it to
    `RuleEntropyFloor(0)` (= 2.0) and re-admit `[2.0, 3.0)`.
  - `internal/scanner/url_secrets.go:40` keeps a hardcoded `e < 2.0`.
    `ExtractURLSecrets` takes no `*rules.RuleSet` and emits `url_*` names that
    are heuristics, not rules, so it structurally cannot honor a per-rule
    threshold. `TestURLSecretsRuleNamesAreNotBuiltinRules` pins that.
  - `internal/scanner/multiline.go:35` keeps **no** entropy gate at all. It
    runs `rule.MatchAll` and reports every span it matches, so on that live
    path (`--multiline` defaults to true) there is no 2.0 floor to align and no
    `entropy_threshold` to read. Out of this batch's blast radius for the same
    reason as above: no `multi_line: true` rule carries a threshold.

### Fixed

- **Batch 6 — `--git-history` now scans the initial commit, so secrets that
  were committed and later deleted are now reported. Finding counts go UP.**

  **This is the one line of this batch that changes what users see, so it is
  stated first and plainly: this batch makes a security tool report things it
  previously stayed silent about.** If you committed a secret and later deleted
  it, `syck scan --git-history` now reports it. Expect the count to rise, not
  fall, and re-scan before concluding anything about what an earlier version
  told you — a clean result from an older version is not evidence of a clean
  history.

  `internal/gitscan/scanner.go` ran `git diff-tree` without `--root`, which
  enumerates no files for the root commit. A secret added in commit 1 and
  `git rm`'d in a later commit was therefore scanned by **nothing**: absent from
  the working tree, and absent from every commit's file list. syck reported
  `Total findings: 0` and exited 0, so CI passed on a repository that still
  contained the secret in its history.

  Reproduced on a two-commit repo (secret in commit 1, `git rm`'d in commit 2),
  before and after:

  | | `Total findings` | exit |
  |---|---|---|
  | before (`37d6c18`) | `0` | `0` |
  | after | `1` — `AKIAIOSFODNN7EXAMPLE` at `git:ed83212c:config.txt` | `2` |

  Exit `2`, not `1`: the finding is CRITICAL, and `cmd/scan_run.go:575` documents
  the default mapping as exit 1 for any finding, exit 2 for CRITICAL.

  The fix is one flag — `--root` on the `diff-tree` call, which diffs the root
  commit against the empty tree and changes nothing for any other commit.

  **Correction to previously shipped documentation.** `ARCHITECTURE.md` §15
  described this defect as meaning "a single-commit repo is completely
  unaudited." That was wrong in practice and is retracted: `cmd/scan_run.go:414`
  runs the ordinary working-tree scan and then *appends* history findings, so a
  single-commit repo was always covered for anything present on disk. The
  narrower, reproduced defect is the one above. `TestScanHistoryFindsCommittedSecret`
  used to commit the secret in a *second* commit to route around this bug; that
  workaround is removed, so the test now exercises the real single-commit case.

  **No duplicate reporting.** Because the root commit's files are now listed, a
  secret that survives into a later commit appears in two diffs. The existing
  `seen` map absorbs it; `TestScanHistoryNoDoubleReportForRootAndLaterCommit`
  pins exactly one finding for a secret present in commits 1 and 3.

- **Batch 6 — `syck scan --git-history` on a non-repository now says so.**
  `gitscan.ScanHistory` returned `(nil, nil)` when `git log` failed, which is
  indistinguishable from a clean scan: `syck scan --git-history /not/a/repo`
  printed `Total findings: 0`, exit 0, and never mentioned that nothing had
  been scanned. It now returns an error naming the path and git's own stderr,
  which the caller prints on stderr:

  ```
  WARNING: git history scan failed: gitscan: git log failed in "/tmp/notarepo": exit status 128: fatal: not a git repository (or any of the parent directories): .git
  ```

  Path shown verbatim from a reproduced run.

  The exit code is still 0 — deliberately unchanged, because promoting this to a
  fatal error is a separate decision with its own blast radius. Note that the
  warning appears *alongside* `Total findings: 0`, not instead of it, so a user
  who only reads the summary still sees zero; read stderr. The old
  `TestScanHistoryNonRepoIsCleanError` pinned the defect by asserting
  `err == nil`; that assertion is inverted and the test is now named
  `TestScanHistoryNonRepoErrors`, which also requires the message to name the
  offending path and to carry git's own stderr.

- **Batch 6 — five `netguard.AllowFetch` SSRF bypasses are closed.** The gate
  rejected a URL only when `net.ParseIP` accepted its host, and `net.ParseIP`
  rejects both the legacy `inet_aton` IPv4 spellings and zone-scoped IPv6. Every
  form below was allowed:

  | URL | Denotes | Now |
  |---|---|---|
  | `http://2130706433/` | `127.0.0.1` (bare 32-bit integer) | denied |
  | `http://127.1/` | `127.0.0.1` (2-part) | denied |
  | `http://010.0.0.1/` | ambiguous — `8.0.0.1` if octal, `10.0.0.1` if decimal | denied |
  | `http://0x7f.0.0.1/` | `127.0.0.1` (hex) | denied |
  | `http://[fe80::1%25eth0]/` | link-local IPv6 with a zone | denied |

  The first, second and fourth rows are *computed*: the legacy parser resolves
  them to an address, which then goes through `IsBlockedIP` like any other
  literal. `010.0.0.1` is different — the two plausible readings disagree, so
  the parser refuses to resolve it at all and the host is denied on ambiguity
  (pinned by `netguard_test.go`, which expects an empty address for it).

  `AllowFetch` now resolves the address those hosts denote and routes it through
  the **same** existing `IsBlockedIP` check — the checks are not waived or
  loosened. url.Parse percent-decodes `%25` during host parsing, so the zone
  arrives as
  `fe80::1%eth0`; the zone is stripped and the remainder re-parsed, which also
  stops `2130706433%foo` from using a zone to smuggle an address past.

  The legacy parser runs only for hosts that could not possibly be DNS names
  (dot-separated parts that are all decimal digits, empty, or `0x`-prefixed
  hex). No registry delegates an all-numeric top-level domain (RFC 3696 §2), so
  that shape is safe to treat as address-shaped. A host of that shape which
  resolves to no valid address is **denied on ambiguity** rather than assumed to
  be a name. `netguard` only ever got tighter: a legacy spelling that denotes a
  public address stays allowed (`134744072` → `8.8.8.8`, `1.2.3` → `1.2.0.3`),
  and DNS names are untouched, including the pinned
  `AllowFetch("http://localhost/") == true`.

  No DNS resolution was added — the "a DNS name that resolves to a private
  address is not detected" gap recorded under the Batch 4c entry above is
  unchanged.

- **`internal/internalurl` now resolves hosts the same way `netguard` does, so
  one URL no longer gets two different answers from the two packages.** This is
  the second half of the fix above, and it **adds findings.** The three parsed
  predicates — `IsPrivateHost`, `IsLoopback`, `IsCloudMetadata` — each called
  `net.ParseIP` directly, so every spelling `net.ParseIP` rejects was invisible
  to them. Once the previous entry made `netguard.AllowFetch` deny exactly those
  spellings, a URL could be "must not be fetched" to the gate and "an ordinary
  public host" to the classifier, in the same process.

  `netguard` now exports the resolver it already owned as
  **`ParseHostIP(host string) (net.IP, bool)`**, and those three predicates call
  it. `AllowFetch` calls the same function, so the package has one parser rather
  than two entry points that could drift apart. `ok` is false for anything that
  is not a literal address — a DNS name *and* an ambiguous legacy host — so no
  caller can read a name as an address.

  Finding counts go **up**, and one category goes up in **severity**:

  | Input | Was | Now | Severity |
  |---|---|---|---|
  | `http://2130706433/` | `""` | `localhost` | Low |
  | `http://127.1/` | `""` | `localhost` | Low |
  | `http://0x7f.0.0.1/` | `""` | `localhost` | Low |
  | `http://10.1/` | `""` | `private_ip` | **Medium** |
  | `http://3232235777/` | `""` | `private_ip` | **Medium** |
  | `http://0xa.0.0.1/` | `""` | `private_ip` | **Medium** |
  | `http://2852039166/` | `""` | `cloud_metadata` | **High** |
  | `http://0xa9fea9fe/` | `""` | `cloud_metadata` | **High** |
  | `http://[::1%25lo]/x` | `""` | `localhost` | Low |

  The last two rows are worth naming. `169.254.169.254` written as a bare
  32-bit integer or in hex *is* the AWS/Azure/GCP metadata endpoint, and recon
  reports that category at **High**. An obfuscated metadata address was silent
  before and is a finding now — the one place where this change raises severity
  rather than adding a Low or Medium.

  Three things deliberately did **not** change:

  - **DNS names.** `example.com`, `localhost`, and `metadata.google.internal`
    behave exactly as before. The legacy parser accepts only hosts whose
    dot-separated parts are all digits or `0x`-prefixed hex, a shape no hostname
    can have; `netguard_test.go` pins that and the new export does not widen it.
    `127.0.0.1.nip.io` is still reported as a public host — see the
    no-compensating-control note under the Batch 4c entry above.
  - **Ambiguous legacy hosts.** `http://010.0.0.1/` reads as `8.0.0.1` under
    inet_aton's octal rule and `10.0.0.1` under a decimal one, and the two
    disagree about a private range. `netguard` denies it on ambiguity; this
    package has no address to classify and so still reports it public. That
    asymmetry is correct — resolving it either way means guessing which of the
    two addresses the author meant.
  - **The classification policy.** `IsPrivateHost` is still RFC 1918 only,
    `IsLoopback` still excludes the private ranges, `IsCloudMetadata` keeps its
    own equality semantics, and link-local (`fe80::/10`) still has no category
    here even though `netguard` blocks it. Only the parser changed. See
    ARCHITECTURE.md §15 item 9's still-open remainder.

### Fixed

- **Batch 7 — distinct secrets that share a long prefix are no longer merged
  into one finding. Finding counts go UP, never down.**

  Two dedup key shapes were truncated, so two different secrets whose keys
  agreed on the truncated prefix collapsed onto one entry and syck reported a
  single finding for what were really two:

  - **Secret-only skip-set keys truncated at 60 chars** — the eight dedup-key
    sites that keyed on the raw secret value alone (`internal/scanner/helpers.go`,
    `scan_content.go`, `scan_file.go`, `scan_stream.go`).
  - **`RuleName + ":" + Secret` cross-commit key truncated at 80 chars** —
    `internal/gitscan/scanner.go`'s per-commit dedup key.

  Both shapes now use the full key. Identical secrets still dedup to one
  finding (the merged-control fixtures pass at every path); distinct secrets
  sharing a 60/80-char prefix that previously surfaced as one finding now
  surface as two. Recorded as §15 item 10 (CLOSED) in ARCHITECTURE.md.

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