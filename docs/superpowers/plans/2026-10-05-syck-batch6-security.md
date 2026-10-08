# SYCK Batch 6 Security Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Fix four reproduced security defects: a silent false negative in git-history scanning, a silent success on a non-repo, and two `netguard` SSRF bypass classes.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch6-security-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Every fix must be proven by a test that fails before it and passes after.** These are security fixes; a fix without a failing-first test is an assertion, not evidence.
- **Netguard may only ever get stricter.** Every change here must deny, never newly allow. If a change would newly permit a URL, it is wrong.
- `netguard_test.go` pins `AllowFetch("http://localhost/") == true` with the comment "Batch 1 checks literal IPs only." **That test must keep passing.** These fixes affect only hosts that parse as literal IPs, never DNS names.
- Gates after every task: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, parity PASS, `go run . ruletest` 40/40.

## The reproduction that defines this batch

```
$ syck scan --git-history <repo where the secret was added in commit 1 and deleted in commit 2>
  Total findings   : 0          # exit code 0
```

A secret that existed only in the first commit is scanned by nothing: absent from the working tree, and `diff-tree` without `--root` never lists it. CI passes.

Also currently allowed by `netguard.AllowFetch` (all verified today):

| URL | Means | Should be |
|---|---|---|
| `http://2130706433/` | `127.0.0.1` | deny |
| `http://127.1/` | `127.0.0.1` | deny |
| `http://010.0.0.1/` | `8.0.0.1` (octal) | deny — leading-zero octal |
| `http://0x7f.0.0.1/` | `127.0.0.1` (hex) | deny |
| `http://[fe80::1%25eth0]/` | link-local IPv6 with a zone | deny |

---

### Task 1: `--root` on `diff-tree`

**Files:**
- Modify: `internal/gitscan/scanner.go:35`
- Modify: `internal/gitscan/scanner_test.go`

- [ ] **Step 1: Write the failing test first**

Add a test that builds a **two-commit** repo where the secret file is added in commit 1 and `git rm`'d in commit 2, then asserts `ScanHistory` finds the secret. The existing `scanner_test.go` already builds real repos with `t.TempDir()` — follow that style exactly.

Run it and **confirm it FAILS.** A test that passes before the fix proves nothing.

- [ ] **Step 2: Add `--root`**

Add the flag to the `diff-tree` invocation. For a root commit this diffs against the empty tree; for every other commit it changes nothing.

Delete the now-obsolete `TODO(security)` comment at `scanner.go:30-34`.

- [ ] **Step 3: Remove the existing test's workaround**

`TestScanHistoryFindsCommittedSecret` currently commits the secret in a **second** commit to route around this bug. Per §15 item 1, that workaround must go — change it to a single commit so it exercises the real case. Verify it still passes.

- [ ] **Step 4: Verify no double-reporting**

`--root` now lists commit 1's files, which a later commit may also touch. The existing `seen` map (keyed `ruleName+secret`) should prevent duplicates, but **prove it**: add a three-commit repo where the same secret is added in commit 1 and modified in commit 3, and assert exactly one finding for that secret.

- [ ] **Step 5: Commit**

```bash
git add internal/gitscan/
git commit -m "fix(gitscan): scan the initial commit with diff-tree --root

A secret committed in the first commit and deleted in a later one was
scanned by nothing: absent from the working tree, and never listed by
diff-tree. syck reported 0 findings and exited 0."
```

---

### Task 2: Non-repo returns a descriptive error

**Files:**
- Modify: `internal/gitscan/scanner.go:21-26`
- Modify: `internal/gitscan/scanner_test.go` — `TestScanHistoryNonRepoIsCleanError`

- [ ] **Step 1: Invert the test that pins the bug**

`TestScanHistoryNonRepoIsCleanError` currently asserts `err == nil` for a directory that was never `git init`'d. That assertion **encodes the defect**. Rewrite it to require a non-nil error, and assert the message names the offending path — a user who asked for history scanning and got nothing must be able to tell that from "no secrets found."

Confirm it fails before the fix.

- [ ] **Step 2: Return a wrapped error**

Replace `return nil, nil` with an error wrapping both the path and the underlying git failure, following the existing wrapping style in the file. Delete the obsolete `TODO(security)`.

- [ ] **Step 3: Check the caller, and do not change its behavior**

`cmd/scan_run.go:429-432` prints `WARNING: git history scan failed: %v` and continues, exiting 0. Per spec §4, **keep that as a warning** — making it fatal is a separate decision with its own blast radius. But confirm the warning is actually visible on stderr and names the path, and note it in your report if it is not.

- [ ] **Step 4: Commit**

```bash
git add internal/gitscan/
git commit -m "fix(gitscan): return a descriptive error for a non-repo path

Previously (nil, nil), so --git-history on a non-repo looked identical to a
clean scan. The caller still downgrades this to a warning; making it fatal is
deliberately left as a separate decision."
```

---

### Task 3: Legacy-IPv4 and IPv6 zone-ID bypasses in `netguard`

**Files:**
- Modify: `internal/netguard/netguard.go`
- Modify: `internal/netguard/netguard_test.go`

**This is the riskiest task in the batch.** The parser must never classify a DNS name as an IP, and must never newly *allow* anything.

- [ ] **Step 1: Extend the table with both polarities, confirm they fail now**

Add cases covering `2130706433`, `127.1`, `010.0.0.1`, `0x7f.0.0.1`, `[fe80::1%25eth0]` — each expected **deny** — plus the boundary on the allow side: a legacy form that denotes a *public* address (`8.8.8.8` equivalents such as `134744072` for `8.8.8.8`, and `1.2.3` for `1.2.0.3`) must stay **allowed**, so the parser is proven to compute the address rather than blanket-denying dotted numerics.

Also pin that plain DNS names are unaffected: `example.com`, and the existing `localhost` allow case.

Run and confirm the deny cases fail before the fix.

- [ ] **Step 2: Legacy-IPv4 parsing**

Go's `net.ParseIP` rejects these forms. Implement an `inet_aton`-style parser that applies **only when the host consists solely of digits, dots, and `0x`/`0`-style prefixes** — i.e. when it could not possibly be a DNS name. Route the resulting `net.IP` through the existing `IsBlockedIP`.

**On ambiguity, deny.** If a host is all digits and dots but does not parse cleanly into a valid IPv4, deny it. A malformed numeric host is far more likely to be an evasion attempt than a legitimate target.

- [ ] **Step 3: IPv6 zone stripping**

`u.Hostname()` returns `fe80::1%eth0` for `http://[fe80::1%25eth0]/`; `net.ParseIP` rejects the zone. Strip the `%zone` suffix before parsing, then run the **same** existing checks — do not skip them, and do not treat a zoned address as automatically public.

- [ ] **Step 4: Verify strictly tighter**

Run: `go test ./internal/netguard/ -count=1 -v`
Expected: all new deny cases pass; **all pre-existing allow cases still pass**, including `http://localhost/` and `http://example.com/`. Any case that flips from deny to allow is a critical regression — stop and report.

- [ ] **Step 5: Commit**

```bash
git add internal/netguard/
git commit -m "fix(netguard): close legacy-IPv4 and IPv6 zone-ID SSRF bypasses

net.ParseIP rejects inet_aton forms (2130706433, 127.1, 010.0.0.1, 0x7f.0.0.1)
and zone-scoped IPv6 (fe80::1%eth0), so all five were allowed. DNS names are
unaffected."
```

---

### Task 4: Docs, and correcting §15

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `ARCHITECTURE.md` §15

- [ ] **Step 1: CHANGELOG**

Record that git-history scanning now covers the initial commit, that previously-invisible findings **will now appear** for anyone whose secrets were committed and later deleted, and that the `netguard` bypasses are closed.

State the visible-output change plainly — this batch makes a security tool report things it previously stayed silent about.

- [ ] **Step 2: Correct §15 items 1 and 2**

Item 1's clause *"a single-commit repo is completely unaudited"* is wrong in practice: `cmd/scan_run.go` runs the ordinary working-tree scan and appends history findings, so a single-commit repo is still covered for anything present on disk. Replace it with the sharper, reproduced statement — **secrets that existed only in the first commit were scanned by nothing**, with the `Total findings: 0` / exit 0 evidence.

Remove items 1, 2, and 4 (zone-ID) once fixed. Leave items 3, 5, 6, 7, 8 in place.

- [ ] **Step 3: Full gates**

Run: `gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, build OK, vet clean, all tests pass, parity PASS, `40 tested, 40 PASSED`.

- [ ] **Step 4: Re-run the original reproduction**

Rebuild the two-commit deleted-secret repo and confirm `syck scan --git-history` now reports the finding. Also confirm a non-repo path now prints a warning naming the path. Quote both outputs — they are the batch's actual evidence.

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md ARCHITECTURE.md
git commit -m "docs: record Batch 6 security fixes and correct the section 15 gitscan entry"
```