# SYCK Batch 4c Shared Internal-URL Predicates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One definition of "private / internal / loopback / cloud-metadata" in the codebase, with the three call sites delegating to it. Zero observable behavior change.

**Architecture:** `internal/netguard` keeps ownership of the IP-range policy (it already owns it from Batch 1) and gains small exported IP-level predicates. A new `internal/internalurl` package layers the recon-facing predicates on top. One direction only: `internalurl` imports `netguard`. `recon` and `jsanalysis` import `internalurl`. No cycle.

**Spec:** `docs/superpowers/specs/2026-10-05-syck-batch4c-internalurl-design.md`

## Global Constraints

- Go 1.26+, module `github.com/RA000WL/syck`.
- **Zero observable behavior change.** `classifyInternal` category strings and severities are user-visible recon output and must be byte-identical for every input. The `jsanalysis` findings must be unchanged.
- **Characterize before refactoring.** Each task that changes a function with no or thin test coverage starts by pinning the current behavior. This is Batch 4's path A rule applied per-task, not just per-batch.
- Parity harness green after every commit: `go test ./internal/scanner/ -run TestParity -count=1`.
- One dependency direction: `internalurl → netguard`. Never the reverse, never both.
- Every task ends green: `go build ./...`, `gofmt -l .` empty, `go vet ./...`, `go test -race ./...`, `go run . ruletest` = 40/40.

## Review Focus

- **Behavior drift in `classifyInternal`.** A delegation that returns `true` where the old regex returned `false` silently changes recon output. The characterization test from Task 3 is the only thing standing between a typo and a shipped output change — check that it actually covers all 7 categories, the precedence order, and the negative case.
- **Regex-vs-CIDR semantic drift.** The old `privateIP10RE` matched the *text* `10.x.x.x` anywhere in the URL, including a path segment or inside a longer hostname. A CIDR check parses the *host*. These differ for inputs like `http://foo.com/10.0.0.1/x` and bare `10.0.0.1` with no scheme. See the mapping table in Task 4 — it is written out explicitly because guessing here changes recon output.
- **Security regression in `netguard`.** `AllowFetch` is Batch 1 security code. Any change must be a pure extraction, and the widened test table must be committed *before* the extraction so a regression is attributable.

## The one intentional behavior change in this batch

Read this before Task 4. Batch 4's contract is zero observable behavior change, and this batch holds to it everywhere **except one input class**, which the approved spec already implied and which is called out here so it is a decision rather than a surprise.

`recon`'s current `localhostRE` is `\b(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0)\b`. That regex is sloppy in two specific ways:

- it matches only `127.0.0.X` — it **misses** `127.1.2.3`, which is loopback
- it **misses** `::1`, which is loopback

`internalurl.IsLoopback` is specified as `127.0.0.0/8, ::1, 0.0.0.0, localhost` — the correct set. Delegating therefore classifies two classes of URL that were previously silent:

- `http://[::1]/x` → now `"localhost"` (was `""`)
- `http://127.1.2.3/x` → now `"localhost"` (was `""`)

There is no way to express the old behavior through a correct `IsLoopback` predicate, because the old behavior was the sloppiness. The alternatives are (a) accept the fix, or (b) keep a regex that deliberately under-matches. This plan takes (a).

**Requirement:** the delta must be recorded in `CHANGELOG.md` under `[Unreleased]` in Task 4, and the Task 3 characterization table must carry `http://[::1]/x` as an **explicit expected-`"localhost"`** row with a comment saying this is the intentional delta — not as a silently-absent case. If a reviewer cannot find both the code change and its CHANGELOG line from the commit alone, the task is not done.

---

### Task 1: Characterize `netguard`, then export IP-level predicates

**Files:**
- Modify: `internal/netguard/netguard_test.go` — widen from 18 lines / 1 table to a full table pinning every claim in the `AllowFetch` doc comment
- Modify: `internal/netguard/netguard.go` — export `IsMetadataHost(host string) bool` and `IsBlockedIP(ip net.IP) bool`; rewrite `AllowFetch`'s body to call them

**Interfaces:**
- Consumes: nothing
- Produces: `netguard.IsMetadataHost(host string) bool`, `netguard.IsBlockedIP(ip net.IP) bool` — both pure additions; `AllowFetch(rawURL string) bool` signature unchanged

**Why this order:** the doc comment claims trailing-dot tolerance, case-insensitivity, and a specific CIDR list. None of it is tested today. Extracting first would mean refactoring behavior nobody has pinned.

- [ ] **Step 1: Widen the test table first, and prove it passes against the CURRENT code**

Add subtests covering, at minimum:
- every address in the current `deny` list (keep them)
- trailing dot: `http://metadata.google.internal./` — the doc comment claims this is denied
- uppercase host: `http://METADATA.GOOGLE.INTERNAL/`
- CIDR boundaries: `172.15.0.1` and `172.32.0.1` must be **allowed**; `172.16.0.0` and `172.31.255.255` denied
- `192.167.0.1` allowed, `192.169.0.1` allowed; `192.168.0.0` denied
- `169.253.0.1` allowed, `169.255.0.1` allowed (link-local boundary)
- `::1` denied; link-local v6 `fe80::1` denied
- `http://localhost/` **allowed** — this is intentional in Batch 1 (no DNS resolution) and the test must say so, so a future reader does not "fix" it into a deny
- unparseable absolute URL denied; bare relative path allowed
- public IPs allowed: `8.8.8.8`, `1.1.1.1`

Run `go test ./internal/netguard/ -v` and confirm **every case passes against the code as it stands today.**

**If any new case FAILS, stop.** That is a real pre-existing bug in Batch 1 security code, not a test error. Report it; do not quietly adjust the test to match the code — that is exactly how a security bug becomes permanent. Record the finding and route it to the user as a separate fix.

- [ ] **Step 2: Commit the tests alone**

```bash
git add internal/netguard/netguard_test.go
git commit -m "test(netguard): pin AllowFetch behavior incl. CIDR boundaries and trailing-dot metadata host"
```

This commit must contain no production change. It is the baseline the extraction is measured against.

- [ ] **Step 3: Export the two predicates**

```go
// IsMetadataHost reports whether host is the well-known GCP metadata hostname.
// Case-insensitive; a trailing dot is tolerated.
func IsMetadataHost(host string) bool

// IsBlockedIP reports whether ip is in a range that must never be fetched:
// 10/8, 172.16/12, 192.168/16, 127/8, ::1, 169.254/16, fe80::/10, 0.0.0.0/::.
// Literal IPs only — callers must have already handled DNS names.
func IsBlockedIP(ip net.IP) bool
```

`IsBlockedIP` holds the existing range loop plus the `IsLoopback` / `IsUnspecified` / `IsLinkLocalUnicast` calls. `IsMetadataHost` holds the existing `metadataHost` comparison including the `TrimSuffix(host, ".")` normalization — that normalization must move with it, not be duplicated at the call site.

- [ ] **Step 4: Rewrite `AllowFetch` to call them**

`AllowFetch` keeps its signature, its doc comment, and its decision order: parse → empty-host handling → metadata hostname → literal IP → allow. Replace the inlined range loop with `if IsBlockedIP(ip) { return false }` and the hostname comparison with `if IsMetadataHost(host) { return false }`. Delete the now-unused private CIDR vars only if nothing else in the package reads them — check before deleting.

- [ ] **Step 5: Verify the extraction changed nothing**

Run: `go test ./internal/netguard/ -count=1 -v && gofmt -l . && go vet ./internal/netguard/`
Expected: all Step 1 cases still pass, gofmt empty, vet clean. Any change in result is a Step 1 miss — go back to Step 1 and add the missing case.

---

### Task 2: New `internal/internalurl` package

**Files:**
- Create: `internal/internalurl/internalurl.go` — the six predicates
- Create: `internal/internalurl/internalurl_test.go` — table tests for each predicate

**Interfaces:**
- Consumes: `netguard.IsBlockedIP`, `netguard.IsMetadataHost`
- Produces:
  ```go
  func IsPrivateHost(rawURL string) bool   // 10/8, 172.16/12, 192.168/16
  func IsLoopback(rawURL string) bool      // 127/8, ::1, 0.0.0.0, "localhost"
  func IsCloudMetadata(rawURL string) bool // 169.254.169.254, metadata.google.internal ± dot
  func IsInternalHost(rawURL string) bool  // internal./corp./.local, *.svc / *.cluster
  func IsInternalPath(rawURL string) bool  // 13-token UNION of recon's internalRE + internalPathRE — see Task 4 table
  func IsSensitivePort(rawURL string) bool // 3306 5432 6379 27017 9200 9300 11211 5984 8500 8600 8200, \b-terminated
  ```

**`IsInternalPath` is a union, not a copy.** `recon` produces its `internal` category from two regexes with different token lists (`internalRE`: internal/private/intranet/corp; `internalPathRE`: debug/trace/admin/internal/private/staging/dev/test/sandbox/legacy/hidden). Taking either one alone drops real matches. The union is 13 distinct tokens: `admin, corp, debug, dev, hidden, internal, intranet, legacy, private, sandbox, staging, test, trace`, matched as `(?i)/(?:...)(?:\b|/|$)`. The trailing group must be `\b|/|$`, not `/|$` — the looser rule is a strict superset, so it reproduces the union exactly.

**`IsSensitivePort` needs its `\b`.** `:(?:3306|5432|...)\b` — without the terminator, port `33060` matches `3306` and every long port in a URL becomes a finding.

**`IsInternalHost` is also a union:** `internalHostRE` (`internal.`/`corp.`/`.local`) plus `k8sServiceRE` (`(?:[a-z0-9-]+\.){1,3}(?:svc|cluster|local|internal)\b`).

**Note on the two notions of loopback:** `netguard.IsBlockedIP` deliberately rejects the DNS name `localhost` — Batch 1 does no DNS resolution. `internalurl.IsLoopback` **must** accept the literal string `localhost`, because `recon` classifies a URL the user typed. Document that difference in a comment on `IsLoopback`; it is deliberate, and a future reader will otherwise "unify" it and break recon.

**Note on raw input:** these take raw URL-or-host strings, including bare hosts with no scheme (`10.0.0.1`). Write one shared `hostOf(raw string) string` helper that returns the parsed hostname when a scheme/authority is present and the lowercased input otherwise — otherwise `IsPrivateHost("10.0.0.1")` returns false because `url.Parse` finds no host, and the whole package is useless.

- [ ] **Step 1: Write the table tests first (TDD), against the specified semantics**

Each predicate gets a table with both polarities. Include the exact inputs from `detector_internal.go`'s current regexes so the delegation in Task 3 can be shown behavior-neutral:

| Predicate | Must be true for | Must be false for |
|---|---|---|
| `IsPrivateHost` | `http://10.0.0.1/`, `172.16.5.4:8080`, `192.168.1.1/admin`, bare `10.1.2.3` | `https://8.8.8.8/`, `172.32.0.1`, `192.169.0.1`, `http://foo.com/10.0.0.1/x` (path, not host) |
| `IsLoopback` | `http://127.0.0.1:8080/`, `http://[::1]/`, `http://0.0.0.0/`, `http://localhost/`, bare `localhost` | `https://example.com/` |
| `IsCloudMetadata` | `http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`, `...internal./` | `http://169.253.0.1/` |
| `IsInternalHost` | `foo.internal/`, `api.corp.example.com`, `db.local`, `svc.cluster`, `a.b.svc` | `https://example.com/` |
| `IsInternalPath` | `/internal/x`, `/admin`, `/staging/api`, `/debug`, `/intranet`, `/corp/x`, `/trace`, `/legacy` | `/api/v1/users` |
| `IsSensitivePort` | `redis://h:6379`, `:5432`, `:27017` | `:8080`, `:443`, `:33060` (the `\b` terminator) |

Run `go test ./internal/internalurl/` — it will fail to compile. That is correct; it is the red step.

- [ ] **Step 2: Implement `hostOf` and the six predicates**

Reuse `netguard.IsBlockedIP` for the CIDR portion rather than re-listing ranges. For `IsPrivateHost`, do **not** use `IsBlockedIP` directly — it also covers loopback and link-local, which would make `IsPrivateHost("http://127.0.0.1/")` true and change `classifyInternal`'s output. You need a narrower primitive. Options: add `netguard.IsPrivateIP(ip net.IP) bool` covering only 10/8, 172.16/12, 192.168/16, and have `IsBlockedIP` call it; or check the three CIDRs locally. Prefer the former — it keeps one CIDR list in the package that owns it. Record which you chose in the report.

- [ ] **Step 3: Verify**

Run: `go test ./internal/internalurl/ -count=1 -v && gofmt -l . && go vet ./internal/internalurl/`
Expected: all tables pass, gofmt empty, vet clean.

- [ ] **Step 4: Commit**

```bash
git add internal/internalurl/
git commit -m "feat(internalurl): single-source predicates for private/loopback/metadata/internal classification"
```

This commit is **inert** — nothing imports the package yet, so no behavior can change.

---

### Task 3: Characterize `classifyInternal`

**Files:**
- Create: `internal/recon/detector_internal_test.go` — characterization table
- Modify: none

**Interfaces:**
- Consumes: nothing
- Produces: a test pinning the current category string for representative inputs

**Why:** `classifyInternal` currently has **zero test coverage** — `grep -rn classifyInternal` finds only its definition and its one call site. Task 4 rewrites its body. Without this task, there is no way to prove the rewrite is behavior-neutral.

- [ ] **Step 1: Write the characterization table**

Pin the category string for at least one input per category, plus the empty-string negative case:

| Input | Expected category |
|---|---|
| `http://internal.corp/api` | `internal` (via `internalRE`) |
| `http://x.com/admin` | `internal` (via `internalPathRE`) |
| `http://x.com/intranet` | `internal` (via `internalRE` only — proves the union is not just `internalPathRE`) |
| `http://x.com/debug` | `internal` (via `internalPathRE` only — the other direction) |
| `http://foo.internal/` | `internal_host` |
| `http://a.b.svc/x` | `internal_host` (via `k8sServiceRE` only) |
| `http://10.0.0.1/x` | `private_ip` |
| `http://172.16.0.1/x` | `private_ip` |
| `http://172.32.0.1/x` | `""` — 172.32 is outside 172.16/12 |
| `http://192.168.0.1/x` | `private_ip` |
| `http://foo.com/10.0.0.1/x` | `private_ip` **today** — the old regex matches raw text; Task 4 changes this to `""` |
| `http://localhost:3000/` | `localhost` |
| `http://127.0.0.5/` | `localhost` |
| `http://[::1]/x` | `""` **today** — Task 4 changes this to `localhost` |
| `http://169.254.169.254/` | `cloud_metadata` |
| `http://metadata.google.internal/` | `""` **today** — Task 4 changes this to `cloud_metadata` |
| `http://docker_host/` | `container_service` |
| `http://h:5432/` | `sensitive_port` |
| `http://h:33060/` | `""` — the `\b` terminator keeps this from matching `:3306` |
| `https://example.com/api/users` | `""` |

The four rows marked **today** carry a comment naming the Task 4 delta. They start at the current value so the test is a true characterization; Task 4 updates exactly those four and nothing else.

Also pin the **precedence** explicitly, since `classifyInternal` is an ordered if-chain: an input that matches two categories must return the earlier one. `http://internal.corp:5432/` matches both `internal` and `sensitive_port` and must return `internal`. `http://10.0.0.1:5432/` matches both `private_ip` and `sensitive_port` and must return `private_ip`.

Derive the expected values by reading the code, then confirm the test passes against the unmodified function.

- [ ] **Step 2: Verify and commit**

Run: `go test ./internal/recon/ -count=1 -v`
Expected: PASS against the **current, unmodified** `classifyInternal`.

```bash
git add internal/recon/detector_internal_test.go
git commit -m "test(recon): characterize classifyInternal categories and precedence before delegation"
```

---

### Task 4: Delegate `classifyInternal` to `internalurl`

**Files:**
- Modify: `internal/recon/detector_internal.go` — replace the regex checks with delegations
- Modify: `CHANGELOG.md` — record the `IsLoopback` delta under `[Unreleased]`

**Interfaces:**
- Consumes: the six `internalurl` predicates
- Produces: `classifyInternal(url string) string` — unchanged signature

**The exact correspondence.** Each category came from one or two regexes with *different* token lists and different trailing rules. Merging them carelessly changes output. Read this table as the specification:

| Category | Current regex(es) | Predicate | Merge note |
|---|---|---|---|
| `internal` | `internalRE` = `(?i)/(internal\|private\|intranet\|corp)(\b\|/\|$)` **OR** `internalPathRE` = `(?i)/(?:debug\|trace\|admin\|internal\|private\|staging\|dev\|test\|sandbox\|legacy\|hidden)(?:/\|$)` | `IsInternalPath` | The union has **13** tokens — neither list alone. Trailing rule must be `\b\|/\|$`: `(?:/\|$)` ⊂ `\b\|/\|$`, so the looser rule makes the union exact. Do not use `(?:/\|$)` — it would drop `/corp` and `/intranet`. |
| `internal_host` | `internalHostRE` = `(?i)(internal\.\|corp\.\|\.local)` **OR** `k8sServiceRE` = `(?i)(?:[a-z0-9-]+\.){1,3}(?:svc\|cluster\|local\|internal)\b` | `IsInternalHost` | Union, not either alone. Note `k8sServiceRE` also matches `.local`/`.internal` suffixes — a superset of `internalHostRE` on those. |
| `private_ip` | `privateIP10RE` / `privateIP172RE` / `privateIP192RE` | `IsPrivateHost` | Text-match on the raw URL becomes a host parse. See the drift note below. |
| `localhost` | `localhostRE` | `IsLoopback` | **The one intentional delta** — see the section above. |
| `cloud_metadata` | `cloudMetadataRE` = `\b169\.254\.169\.254\b` | `IsCloudMetadata` | Also adds `metadata.google.internal`, which the old regex did **not** match. Same delta treatment: CHANGELOG it. |
| `container_service` | `dockerServiceRE` = `(?i)(?:docker\|container)[_.]?(?:host\|name\|id\|service)\b` | keep local | No shared predicate — this vocabulary appears nowhere else. Leave the regex. |
| `sensitive_port` | `sensitivePortRE` = `:(?:3306\|5432\|6379\|27017\|9200\|9300\|11211\|5984\|8500\|8600\|8200)\b` | `IsSensitivePort` | Keep the `\b` terminator; a port list without it matches `:33060`. |

**Known drift for `private_ip`:** the old regexes matched the text `10.x.x.x` anywhere, so `http://foo.com/10.0.0.1/x` and a bare `10.0.0.1` both classified as `private_ip`. `IsPrivateHost` parses the host, so `http://foo.com/10.0.0.1/x` becomes `""`. Pin that input in the Task 3 table with its **current** value and let the delegation change it — a private IP in a path is not a private-IP host, so the new answer is the better one. CHANGELOG it alongside the loopback delta.

- [ ] **Step 1: Replace the seven checks, preserving order exactly**

Keep the if-chain order verbatim — it is a precedence chain, and `http://internal.corp:5432/` must still return `internal`, not `sensitive_port`.

Delete only the regexes whose sole consumer is `classifyInternal`. **Check with `grep -rn` before deleting each one** — `internalRE`, `internalHostRE`, `k8sServiceRE`, `privateIP10RE`, `privateIP172RE`, `privateIP192RE`, `localhostRE`, `cloudMetadataRE`, `internalPathRE`, `sensitivePortRE` must each have no other reference in package `recon`. `dockerServiceRE` **stays**. Do not touch the package's other detectors.

- [ ] **Step 2: Verify behavior is unchanged apart from the declared deltas**

Run: `go test ./internal/recon/ -count=1 -v`
Expected: the Task 3 characterization table passes with **only** the rows marked as intentional deltas updated — `http://[::1]/x`, `http://127.1.2.3/x`, `http://metadata.google.internal/` (now `cloud_metadata`), and `http://foo.com/10.0.0.1/x` (now `""`). **Any other row that changes is a bug in the mapping above** — fix the mapping, not the test.

- [ ] **Step 3: Record the deltas in `CHANGELOG.md`**

Under `[Unreleased]`, note that recon's internal-surface detection now recognizes IPv6 loopback (`[::1]`), non-`127.0.0.x` loopback addresses, the GCP metadata hostname, and no longer reports a bare private IP appearing in a URL path as a `private_ip` surface finding.

- [ ] **Step 4: Run the wider gates**

Run: `go build ./... && go vet ./... && gofmt -l . && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`
Expected: all clean, parity PASS, ruletest 40/40.

- [ ] **Step 5: Commit**

```bash
git add internal/recon/detector_internal.go internal/recon/detector_internal_test.go CHANGELOG.md
git commit -m "refactor(recon): delegate classifyInternal to shared internalurl predicates"
```

---

### Task 5: Delegate the jsanalysis loopback check

**Files:**
- Modify: `internal/jsanalysis/analyze.go` — the `localhostRE` use at line ~194

**Interfaces:**
- Consumes: `internalurl.IsLoopback`
- Produces: unchanged findings

**Scope limit:** `internalServiceRE` stays. It is an **extractor** (it captures the config value after `internal:`), not a classifier — sharing it with `classifyInternal` would be the behavior-destroying merge the spec rejects. `localhostRE` is also an extractor, but it matches a narrow literal set; the question for this task is whether delegating changes the finding set, and the answer must be **no**.

- [ ] **Step 1: Characterize before changing**

Add a test in `internal/jsanalysis` pinning the findings produced for a JS line containing `localhost:8080`, `127.0.0.1:3000`, and `0.0.0.0:9000`, plus a negative (`example.com:8080`). Confirm it passes against current code.

- [ ] **Step 2: Make the delegation**

If the finding set can be preserved, delegate. **If preserving it requires a regex anyway, keep the regex and skip this task** — report that. A predicate call that must be wrapped in a regex to keep the same output is not a simplification. `internal/endpoints/extract.go` stays untouched entirely.

- [ ] **Step 3: Verify and commit**

Run: `go test ./internal/jsanalysis/ -count=1 && go test ./internal/scanner/ -run TestParity -count=1`
Expected: characterization test unchanged, parity PASS.

```bash
git add internal/jsanalysis/
git commit -m "refactor(jsanalysis): delegate loopback detection to internalurl (or: no-op if unwrappable)"
```

---

### Task 6: Resolve the V1/V6 documentation contradiction

**Files:**
- Modify: `internal/scanner/scanner.go` — package doc comment
- Modify: `ARCHITECTURE.md` — the `pipeline.go` line in §3, and the V1/V6 wording in §4

**Interfaces:**
- Consumes: nothing
- Produces: docs that state the truth

**The current doc is backwards.** `scanner.go` says "Package scanner is the V1 pipeline entry point" and calls `ScanPaths`/`ScanFile`/`ScanReader`/`ScanURLs`/`ScanContent` "the legacy V6 entry points". `ARCHITECTURE.md` §4 says the opposite — "The CLI uses the V6 inline orchestration path." The V6 entry points are the **live** ones; `Pipeline` is the test-only one. Fix the doc to match reality. Delete nothing.

- [ ] **Step 1: Rewrite the package doc** to say: the V6 entry points are the CLI scan path; `Pipeline` and the `stage_*.go` types exist for tests and are not on the CLI path; do not wire new CLI work through them. Describe what they are without prescribing their removal.

- [ ] **Step 2: Align `ARCHITECTURE.md`** so §3's `pipeline.go` annotation and §4's V1/V6 wording agree with the package doc. One sentence of orientation, not a restructure.

- [ ] **Step 3: Full gates**

Run: `gofmt -l . && go build ./... && go vet ./... && go test -race ./... && go test ./internal/scanner/ -run TestParity -count=1 && go run . ruletest 2>&1 | tail -1`
Expected: gofmt empty, build OK, vet clean, all tests pass, parity PASS, ruletest 40/40.

- [ ] **Step 4: Commit**

```bash
git add internal/scanner/scanner.go ARCHITECTURE.md
git commit -m "docs(scanner): correct V1/V6 entry-point description; mark Pipeline test-only"
```