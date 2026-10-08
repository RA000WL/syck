# Changelog

All notable changes to syck are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased] — Batch 6: security fixes (**adds findings**) + Batch 4c: shared internal-URL predicates (**breaking**) + Batch 3: performance + Batch 5: entropy-floor consistency + Batch 7: dedup-key truncation fix (**adds findings**) + Batch 8: FP/context filters on the lagging paths (**removes findings**, one CRITICAL class restored) + Batch 9: FP filters on the multi-line path (**removes findings**) + Batch 10: localhostRE loopback vocabulary and anchoring (**adds findings**, changes emitted strings)

This section carries eight batches, so the title names them and flags the four
that change visible output. **Read the Batch 6 entry first if you are diffing
finding counts between versions: it makes syck report findings it previously
stayed silent about, so finding counts go UP.** Batch 6 is listed first for
that reason and is not breaking in the API sense. Batch 4c **changes** recon's
internal-surface output, including a class of input that no longer produces a
High-severity finding. Batch 3 (performance work) is not breaking. Batch 5 is a
detection-consistency fix that **removes** findings on two paths; it is not
breaking and touches no public API. Batch 7, like Batch 6, makes finding
counts go **UP**: distinct secrets that share a long prefix used to be merged
into a single finding (see its entry under "### Fixed" below). Batch 8 runs the
other way — it **removes** false positives on three rule-matching paths — with
one deliberate exception, stated in its own entry: it restores CRITICAL
private-key blocks on the decoded path, which is a count going **up** for one
class. Batch 9 removes false positives on the fourth path (multi-line) and
keeps the same private-key blocks reported on it, so no CRITICAL class is
lost. Batch 10 also goes **up** for three classes of JavaScript-loopback
config value, and additionally **changes the string reported** for a fourth
class — a loopback token embedded in a longer hostname now reports the whole
host instead of a carved-up substring. Diffing on that emitted substring needs
a read of its table, not just a count.

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

### Fixed

- **Batch 8 — `internal/jsrecon`, `internal/json_scanner` and the decoder's
  decoded-content path now apply the plain-file path's false-positive and
  context filters. Finding counts go DOWN.**

  Batch 5 made the entropy floor consistent across these three paths. The
  context guard and the three `IsFalsePositive*` filters were still missing, so
  the same input that was silent on the plain-file path could still produce a
  finding there. They are now applied in the plain-file path's order
  (`internal/scanner/helpers.go:529`, then `:555-563`): `RequiresContext`
  first — it needs the source text, before secret extraction narrows it — then,
  after secret extraction and the entropy floor, `IsFalsePositiveSecret`,
  `IsFalsePositiveToken`, `IsFalsePositiveEmail`.

  | Path | Call site | What was added |
  |---|---|---|
  | `internal/jsrecon/reconstruct.go` (`scanReconstructed`) | `:416`, `:437-445` | `RequiresContext` + all three FP filters |
  | `internal/json_scanner/scanner.go` (`scanValue`, ruleset branch) | `:112`, `:134-142` | `RequiresContext` + all three FP filters |
  | `internal/decoder/pipeline.go` (`scanDecodedChunk`) | `:168`, `:182` | `RequiresContext` + `IsFalsePositiveSecret`; `Token`/`Email` were already applied at `:206`/`:209` and were left where they were, so each filter runs once |

  Each `RequiresContext` check runs against the text that path actually matches
  rules against, not against a narrower slice, so none of the three became
  stricter than the plain path: jsrecon checks the **reconstructed string** (a
  fragment synthesized from two or more JS lines has no natural source line —
  `lineno` records only where the fragment started), json_scanner checks the
  **key path plus the value** (that is what `{"<key>":"<value>"}` offers a
  plain file), and the decoder checks the **decoded chunk** (the source line is
  the encoded blob, whose keywords are whatever the caller happened to write
  beside it). The choice and its reason are recorded in a comment at each site.

  Measured on the seven-fixture premise corpus committed in
  `internal/{jsrecon,json_scanner,decoder}/fp_filter_test.go`, each fixture
  driven through all three paths and the emitted findings diffed:

  | Path | Before | After | Removed | Added |
  |---|---|---|---|---|
  | jsrecon | 9 | 3 | 6 | **0** |
  | json_scanner | 9 | 3 | 6 | **0** |
  | decoder | 5 | 3 | 2 | **0** |
  | **total** | **23** | **9** | **14** | **0** |

  **No new secret span is reported.** The diff between the two runs is a strict
  subset: every (rule, span) pair present after was present before. On the
  decoder path that claim needs stating precisely, because `scanDecodedChunk`
  dedups on the secret value alone (`pipeline.go:213-222`): suppressing a
  finding for secret *S* can let a later rule that also matches *S* win the
  slot, so a surviving finding's `RuleName`/`Severity` **can** change even
  though the set of reported secret spans cannot grow. In this corpus it does
  not — every surviving span had exactly one surviving rule.

  What stops being reported, by filter: 7 placeholder-value spans
  (`secret='user_name_d9f3a7c2b8e5d4'` is a config key name in a secret-shaped
  slot; `IsFalsePositiveSecret` pulls the quoted value out via
  `kvPlaceholderRe` and Token's snake_case branch rejects it), 3 context-less
  auth spans (`basic_auth_header` with no context keyword anywhere in the
  scanned text — this is the guard that was inert before), 2 hyphen-token spans
  (`vault_token` on `hvs.a7f3-b9c2-d4e6-8f01`, Token's `>= 3` hyphens and
  `len > 20` branch) and 2 image-filename email spans (`email_address` on
  `opengraph-image@2x.jpeg`, Email's image/font-extension list).

  What still gets reported, on every path: `basic_auth_header` **with**
  `Authorization:` present (the negative control for the context guard — the
  guard is not "drop every `requires_context` rule"), `stripe_secret_key` and
  `env_generic_secret`. Note that `env_generic_secret` cannot be made
  context-less by any input: its four pattern alternatives each contain a
  literal (`_SECRET`, `_PASSWORD`, `_TOKEN`, `_API_KEY`) that is one of its own
  `context_keywords`, so every match carries its own keyword. That is pinned by
  three premise tests, one per path.

  **This is a false-positive reduction, so a re-scan of the same target
  reports fewer findings than before.** The suppressed shapes are still
  scanned; they are now judged the way the plain-file path judges them.

- **Batch 8 correction (`983ffab`) — `IsFalsePositiveToken` is not applied to
  `multi_line` rules on the decoded path, so CRITICAL PEM private-key blocks
  are still reported through decoded content. This is the one count in this
  batch that goes UP, deliberately.**

  `IsFalsePositiveToken`'s hyphen heuristic (`>= 3` hyphens and `len > 20`,
  aimed at feature-flag names) cannot tell a full PEM block from a feature
  flag: a PEM block is nothing but hyphens and base64. The decoder iterates
  every rule, the `multi_line` ones included, and `rsa_private_key`,
  `ec_private_key`, `openssh_private_key` and `pgp_private_key` are CRITICAL
  and exist precisely so base64-decoded content can be scanned.

  This is not a policy change, and the earlier framing of it as "parity" was
  too weak. The single-line path does report nothing for the header line
  (`scanLineForRegexRules` on `-----BEGIN RSA PRIVATE KEY-----` → 0 findings),
  but `internal/scanner/multiline.go` applies **no filters at all** and still
  reports the full block as **CRITICAL** from a plain file: `ScanMultiLine`
  over a four-line block yields `rsa_private_key_multiline` at severity
  CRITICAL, and `syck scan` on a real PEM file reports `Total findings: 1`,
  all CRITICAL, exit 2. So base64-encoded key material would have been *less*
  visible than the same material sitting on disk — a decoded-path loss, not a
  consistency win.

  Measured: a shape-accurate PEM block arriving base64-encoded on the decoded
  path goes from **0 findings to 1** — `base64_rsa_private_key`, CRITICAL. That
  suppression predates this batch (the decoded path applied Token before Batch
  8 too, at what was then `pipeline.go:171`), so the carve-out closes a
  pre-existing decoded-path gap rather than repairing damage this batch caused —
  which is also why it belongs in this entry: it is the correction that keeps
  the decoded path seeing what a plain file already shows.
  `IsFalsePositiveSecret` and `IsFalsePositiveEmail` stay applied to
  `multi_line` rules on that path: they are span-shape-agnostic (placeholders
  and image-filename addresses are false positives at any length and arity),
  unlike Token. `TestDecodedPathPEMBlockReported` pins the block and
  `TestDecodedPathHyphenatedFlagStillSuppressed` pins the control, so the
  carve-out cannot silently widen into "Token never applies".

  **Residual, recorded rather than fixed:** the carve-out is decoder-only. The
  same block reached through `internal/jsrecon` or `internal/json_scanner` is
  still suppressed by Token (`rsa_private_key`'s span scores 5.5420 entropy
  and `IsFalsePositiveToken` returns true for it), as is the header line on
  every path including the plain one. Those shapes remain visible where the
  content is a plain file.

### Fixed

- **Batch 9 — `internal/scanner/multiline.go` now applies the entropy floor,
  the `RequiresContext` guard and the `IsFalsePositive*` filters. Finding
  counts go DOWN. This was the last rule-matching path with no filters at all.**

  The multi-line path is default-on (`--multiline` defaults to true and
  `internal/lsp/server.go:180` forces it on), so every span matched by any
  `multi_line` rule was reported unconditionally — with no entropy floor, no
  `IsFalsePositiveSecret`, no `IsFalsePositiveToken`, no
  `IsFalsePositiveEmail` and no `RequiresContext`. Batch 5 aligned the floor on
  the paths that *had* one and Batch 8 added the context guard plus the three
  FP filters to the decoded, jsrecon and json_scanner paths; this file was
  §15 item 7's remaining path, and the hardest of the four because it had no
  floor to align to.

  All four filters now apply in the plain-file path's order
  (`internal/scanner/helpers.go:529`, then `:555-563`): `RequiresContext`
  first — it needs the window text, before secret extraction narrows it — then
  secret extraction, then `decoder.RuleEntropyFloor(rule.EntropyThreshold)`,
  then `IsFalsePositiveSecret` → `IsFalsePositiveToken` → `IsFalsePositiveEmail`.
  The context text is the whole joined window, matching the decoded path's
  choice of "the text this path matches rules against"
  (`internal/decoder/pipeline.go:160-170`) rather than the per-line path's
  single line.

  **`IsFalsePositiveToken` is exempted for multi-line spans, and that exemption
  is the reason this batch was written carefully.** Token's hyphen heuristic
  (`>= 3` hyphens and `len > 20`, aimed at feature-flag names) cannot tell a
  full PEM block from a feature flag — a PEM block is nothing but hyphens and
  base64. Measured on the fabricated fixtures in
  `internal/scanner/multiline_filter_test.go`, every private/public-key block
  trips it while clearing the 2.0 floor with room to spare:

  | fixture | span entropy | below 2.0 floor? | `IsFalsePositiveToken` |
  |---|---|---|---|
  | `rsa_private_key` | 5.542 | no | **true** |
  | `ec_private_key` | 3.952 | no | **true** |
  | `openssh_private_key` | 4.640 | no | **true** |
  | `pgp_private_key` | 4.082 | no | **true** |
  | `rsa_public_key` | 4.496 | no | **true** |

  Applying Token here would have suppressed the CRITICAL private-key rules on
  the one default-on path whose `multi_line` patterns exist to report whole
  blocks — strictly worse than the decoded-path loss Batch 8 corrected. The
  exemption is unconditional rather than guarded by `!rule.MultiLine` because
  `ScanMultiLine`'s loop already skips every non-multi_line rule, so the guard
  would be dead code. It is the same carve-out and the same reason as
  `internal/decoder/pipeline.go:190-208`; `TestMultiLinePEMBlockStillReported`
  pins the blocks and asserts first that each fixture really does trip Token,
  so the guard cannot pass for the wrong reason.

  Two of the four filters are parity, not effect, for today's ruleset, and are
  recorded so a future reader does not expect suppression from them:
  `RequiresContext` — none of the 9 `multi_line` rules in
  `internal/rules/builtin.yaml` sets `requires_context` (nor `entropy_threshold`,
  so the floor is the global `decoder.RuleEntropyFloor(0)` = 2.0), so the branch
  is inert now and starts working the moment a `multi_line` rule sets it; and
  `IsFalsePositiveEmail` — no `multi_line` rule matches email-shaped text, so
  nothing on this path can be an `opengraph-image@2x.png` false positive.
  `IsFalsePositiveSecret` is also effectively unreachable here, and that is a
  gap rather than a parity note: its `kvPlaceholderRe` is anchored `^...$` and
  its capture cannot cross the newline that both structured `multi_line` rules
  require, so the `KEY=value` it looks for is never present in a multi-line
  span. A docker-compose secret whose value is the literal `changeme` still
  reports, at HIGH — pinned by `TestMultiLineResidualPlaceholderStillReported`.

  Measured over the fixture corpus in
  `internal/scanner/multiline_filter_test.go`, each fixture a full window
  handed to `ScanMultiLine` and the whole findings slice asserted (so an added
  finding fails the test as hard as a removed one):

  | Fixture | Span entropy | Before | After |
  |---|---|---|---|
  | `pem_rsa_private_key` | 5.542 | 1 (CRITICAL) | 1 (CRITICAL) |
  | `pem_ec_private_key` | 3.952 | 1 (CRITICAL) | 1 (CRITICAL) |
  | `pem_openssh_private_key` | 4.640 | 1 (CRITICAL) | 1 (CRITICAL) |
  | `pem_pgp_private_key` | 4.082 | 1 (HIGH) | 1 (HIGH) |
  | `rsa_public_key` | 4.496 | 1 (MEDIUM) | 1 (MEDIUM) |
  | `kubernetes_secret` | 4.111 | 1 (HIGH) | 1 (HIGH) |
  | `docker_compose_secret` | 4.894 | 1 (HIGH) | 1 (HIGH) |
  | `docker_compose_low_entropy_value` (96 repeated chars) | 1.756 | 1 (HIGH) | **0** |
  | `docker_compose_low_entropy_boundary` (72 repeated chars) | 2.059 | 1 (HIGH) | 1 (HIGH) |
  | **total** | | **10** | **9** |

  The single removal is a run of repeated characters, which is the only shape
  the floor rejects on these rules. The paired boundary case exists so the
  suppression is attributable to the value's entropy rather than to the
  docker-compose shape: measured on the same realistic window, 48 repeated
  chars score 2.500 and 64 score 2.187 (both reported), 72 scores 2.059
  (reported), 80 scores 1.946, 96 score 1.756, 128 score 1.474 and 200 score
  1.093 (all suppressed). The same boundary shows through `syck scan` on real
  files, not only through the unit fixtures: a `docker-compose.yml` with
  `PASSWORD: "<64 a's>"` still reports (`entropy: 2.187`), while 96, 128 and
  200 report nothing.

  **This is a false-positive reduction, so a re-scan of the same target reports
  fewer findings than before**, on a default-on path. No real key-shaped span is
  affected: every multi-line span the builtin rules can match on a realistic
  input clears the floor, and the private-key rules are untouched.

### Changed

- **Batch 10 — the JavaScript analyzer's loopback extractor now recognizes the
  whole loopback set and reports whole hosts.** `localhostRE` in
  `internal/jsanalysis/analyze.go` knew three spellings (`localhost`,
  `127.0.0.1`, `0.0.0.0`), was case-sensitive, required `127.0.0.1` exactly
  rather than `127/8`, had no IPv6 rule, and was unanchored — so it carved a
  *subspan* out of a longer host. Findings go **up** for three classes and the
  reported string **changes** for a fourth. The two halves are one change: a
  widened token list on an unanchored pattern would only have traded
  under-matches for wrong findings.

  The pattern is now:

  ```
  (?i)(?:^|[^A-Za-z0-9._-])((?:[A-Za-z0-9_-]*[.-])*LOOPBACK:\d+)
  ```

  anchored at a host-token boundary (a character class, **not** `\b` — both `-`
  and `.` are non-word characters, so `\b` still matches at the seam in
  `my-localhost` and `foo.localhost`), with the loopback vocabulary `localhost`
  in any case, all of `127/8` as dotted quads with `0`-`255` octets, `0.0.0.0`,
  and bracketed `[::1]`. The `:port` requirement and the port shape are
  unchanged — it is what makes this a service-address finding rather than a bare
  hostname.

  | Input | Before | After |
  |---|---|---|
  | `http://my-localhost:8080/` | `localhost:8080` | `my-localhost:8080` |
  | `var db = "LOCALHOST:8080"` | *(nothing)* | `LOCALHOST:8080` |
  | `var db = "127.0.0.2:8080"` | *(nothing)* | `127.0.0.2:8080` |
  | `var db = "[::1]:8080"` | *(nothing)* | `[::1]:8080` |
  | `var db = "localhost:8080"` | `localhost:8080` | `localhost:8080` |
  | `var db = "example.com:8080"` | *(nothing)* | *(nothing)* |

  **Read the first row before diffing finding counts.** A loopback token
  embedded in a longer hostname is no longer carved into a subspan: the
  reported string changes from `localhost:8080` to the whole host the author
  typed, `my-localhost:8080`. Anyone keying on the emitted substring — a
  post-processing script, a suppression rule, a golden file — will see a diff.
  The finding is not lost, only renamed, for `foo.localhost:8080`,
  `my-localhost:8080`, and `.localhost:8080` alike.

  Anchoring removes one smaller class outright. A token glued to the *front* of
  a label is not a host, so `notlocalhost:8080` no longer reports
  `localhost:8080` — that was a false positive, and the count for it goes
  **down**. Likewise `localhost.example.com:8080`: the loopback label is not the
  final label of the host, so the whole host is a public one and nothing is
  reported.

  Both halves were verified by differential run over 52,920 generated
  token/separator/port combinations against the previous pattern: 8,232 inputs
  gained a finding (all three widened classes), 4,410 changed the reported
  string (all whole-host), 1,372 lost one (all glued-token carve-ups). No other
  input class moved. `TestLocalhostRE_SixInputs`,
  `TestLocalhostRE_AnchoringBounds`, `TestLocalhostRE_VocabularyBounds` and
  `TestLocalhostRE_UnchangedShapes` pin the table above; the before-picture is
  preserved in the table inside `TestLocalhostRE_SixInputs`.

  `internalurl.IsLoopback` accepts a strictly larger vocabulary than this
  extractor does — portless `localhost`, `127.1`, `2130706433`, a zoned
  `[::1%25lo]` — and still answers false for `my-localhost`. **Delegation is
  closer, and still not done**; it would move findings in both directions and
  need its own entry. See the tripwire comment at the declaration and
  `ARCHITECTURE.md` §15 item 3.

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