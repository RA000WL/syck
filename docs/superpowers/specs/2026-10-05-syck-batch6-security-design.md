# SYCK Batch 6 — Security: Silent FN + SSRF Bypasses — Design Spec

Date: 2026-10-08
Status: reproduced end-to-end; scope is four small, independent fixes

## 1. Intent

Clear the security half of the deferred queue. Four defects, all reproduced before planning, all in code this project has already flagged and deferred. Three are silent; one is a latent bypass class.

Reproduced today:

| # | Defect | Reproduction | Observed |
|---|---|---|---|
| A | gitscan initial commit never scanned | 2-commit repo: secret added in commit 1, deleted in commit 2 | `Total findings: 0`, **exit 0** |
| B | gitscan non-repo silent success | `syck scan --git-history /not/a/repo` | returns `(nil, nil)`, no error |
| C | `netguard` legacy-IPv4 bypass | `AllowFetch("http://2130706433/")` | returns **true** (it is `127.0.0.1`) |
| D | `netguard` IPv6 zone-ID bypass | `AllowFetch("http://[fe80::1%25eth0]/")` | returns **true** |

## 2. Correction to the existing §15 record

§15 item 1 currently reads: *"the first commit of a repo yields no files. Secrets committed in a repo's FIRST commit are invisible to `--git-history`, and a single-commit repo is completely unaudited."*

**The second clause is wrong in practice.** `cmd/scan_run.go:414-431` runs `scanner.ScanPaths(args)` **and then appends** history findings, so for a single-commit repo the ordinary working-tree scan already finds anything still present on disk. Verified: scanning a one-commit repo returns `2` findings with ordinary filesystem paths, not `git:<sha>:` paths.

The real, sharper defect: **a secret committed in the first commit and subsequently deleted is never scanned by anything** — it is absent from the working tree, and `diff-tree` without `--root` never lists it. Exit code 0, so CI passes. Correct §15 alongside the fix.

## 3. The four fixes

### A. `--root` on `diff-tree`

`internal/gitscan/scanner.go:35` adds `--root`. For a root commit this diffs against the empty tree, yielding its added files; for every other commit `--root` changes nothing. The existing `seen` map already dedups by `ruleName+secret`, so a file touched in several commits is not double-reported.

`TestScanHistoryFindsCommittedSecret` currently works around the bug with a second commit; that workaround must be removed so the test exercises one commit.

**Also fix the exit-code behavior.** With A applied, a repo whose only secret was in commit 1 now produces findings. But the deeper issue is that `ScanHistory` returning `(nil, nil)` on a git error lets the caller print a warning and continue with exit 0. After B, `ScanHistory` returns a real error; decide explicitly whether that is fatal (see §4).

### B. Non-repo returns a descriptive error

Replace `return nil, nil` with a wrapped error naming the path and the underlying git failure. The existing `TestScanHistoryNonRepoIsCleanError` pins `err == nil` and **must be inverted** — it currently encodes the bug.

### C. Legacy IPv4 forms

`net.ParseIP` rejects `010.0.0.1` (leading zero = octal in `inet_aton`), `127.1` (2-part), `2130706433` (32-bit integer), and `0x7f.0.0.1`. All denote real addresses and are accepted by many clients, so `AllowFetch` returning true for them is a bypass for the fetch path.

Implement an `inet_aton`-style parser for a host that is entirely digits, dots, and `0x`/`0` prefixes, and route the result through the existing `IsBlockedIP`. **Only apply it when the host parses as a legacy form** — never reclassify a DNS name.

### D. IPv6 zone identifiers

`u.Hostname()` on `http://[fe80::1%25eth0]/` yields `fe80::1%eth0`; `net.ParseIP` rejects the zone, so link-local IPv6 with a zone escapes the gate. Strip the `%zone` suffix before parsing, then apply the existing link-local check.

## 4. One decision required: is a git failure fatal?

Today `cmd/scan_run.go:429-432` prints `WARNING: git history scan failed` and continues, exiting 0. With B in place, `--git-history /not/a/repo` would still exit 0 with only a warning.

That is defensible (the ordinary scan still ran) and it is what the current design intends. **Recommendation: keep it a warning, but make it loud** — the error must name the path and the git failure so a user who asked for history scanning and got none can tell that from "no secrets found." Changing it to fatal is a separate decision with its own blast radius; note it, do not bundle it.

## 5. Testing

Characterize before fixing, per the pattern the last four batches established:

- **A**: a test that builds a two-commit repo where the secret is added then deleted, and asserts the secret is found. It must fail before the fix. Building real git repos in tests is already done (`TestScanHistoryFindsCommittedSecret` does it), so follow that style.
- **B**: invert `TestScanHistoryNonRepoIsCleanError` to require a non-nil error naming the path.
- **C/D**: extend `netguard`'s table with the legacy-IPv4 and zone-ID forms on both the allow and deny sides, so the boundary is pinned rather than the happy path.

## 6. Risks

- **`--root` could double-report.** It should not (the `seen` map), but verify: a file added in commit 1 and modified in commit 3 must yield one finding per secret, not two.
- **The legacy-IPv4 parser is the riskiest piece.** It must not classify a DNS name as an IP, must not mis-parse a valid dotted quad, and must not accept a malformed form as a public IP and thereby *allow* something it should deny. Prefer denying on ambiguity: if a host is all-numeric-and-dots but does not parse cleanly, deny.
- **Zone stripping must not admit a routable host.** Strip the zone, then run the *same* checks — do not skip them.
- **Fixing A makes previously-silent findings appear.** That is the point, but it is a visible change in output for anyone scanning repos whose secrets were committed and deleted. `CHANGELOG.md` must say so explicitly.
- `netguard_test.go` currently pins `AllowFetch("http://localhost/") == true` with a comment that Batch 1 does no DNS resolution. C and D do **not** change that — they only affect hosts that parse as literal IPs. Keep that test passing.