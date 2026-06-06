# FP Rule Tightening + JDBC URL Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate 9 false positives in 2 rules (`notion_api_token`, `airtable_api_key`) and recover 4 missed JDBC connection strings by adding `jdbc:` prefix support to 3 database URL rules.

**Architecture:** Single-file change to `internal/rules/builtin.yaml` (5 `pattern:` fields updated). Validation is empirical: re-scan `/tmp/wrongsecrets/` before and after, diff the per-rule finding counts. No unit-test fixtures, no CI changes, no new files.

**Tech Stack:** Go 1.26+, GoReleaser, syck CLI, Python 3 for diff.

---

## File Structure

This plan touches exactly one source file:

- **Modify:** `internal/rules/builtin.yaml` — 5 rules updated:
  - `notion_api_token` (line 383): length tightening
  - `airtable_api_key` (line 593): exact length + digit lookahead
  - `postgres_url` (line 631): `jdbc:` prefix + query-string path chars
  - `mysql_url` (line 635): same
  - `mongodb_url` (line ~641): same

No new files. No test changes. No documentation changes (the rule tightening is internal; no user-facing flag/behavior changes).

---

## Task 1: Capture before-fix baseline

**Files:**
- Read: `/tmp/wrongsecrets_results.json` (already exists from prior syck run)
- Create: `/tmp/syck-wrongsecrets-before.json` (copy of existing baseline)

- [ ] **Step 1: Verify the baseline JSON exists and is recent**

```bash
ls -la /tmp/wrongsecrets_results.json
```

Expected: file exists, size > 1KB, mtime within the past day.

- [ ] **Step 2: Copy baseline to a clearly-named file**

```bash
cp /tmp/wrongsecrets_results.json /tmp/syck-wrongsecrets-before.json
ls -la /tmp/syck-wrongsecrets-before.json
```

Expected: file exists, identical size to source.

- [ ] **Step 3: Confirm baseline shows the 9 expected FPs and 0 JDBC findings**

```bash
python3 -c "
import json
d = json.load(open('/tmp/syck-wrongsecrets-before.json'))['findings']
c = {}
for f in d:
    c[f['rule']] = c.get(f['rule'], 0) + 1
for r in ['notion_api_token', 'airtable_api_key', 'postgres_url', 'mysql_url', 'mongodb_url']:
    print(f'{r:30s} {c.get(r, 0)}')
"
```

Expected output:
```
notion_api_token              7
airtable_api_key              2
postgres_url                  0
mysql_url                     0
mongodb_url                   0
```

If any of these numbers is wrong (e.g. `notion_api_token != 7`), the baseline is stale or the wrongsecrets/ corpus was modified. Re-run syck to refresh:

```bash
syck scan /tmp/wrongsecrets --format json -o /tmp/syck-wrongsecrets-before.json
```

- [ ] **Step 4: No commit needed (no code changes in this task)**

---

## Task 2: Apply notion_api_token length tightening

**Files:**
- Modify: `internal/rules/builtin.yaml:385` (the `pattern:` line of `notion_api_token`)

- [ ] **Step 1: Open the rule file and locate the rule**

```bash
grep -n "notion_api_token" internal/rules/builtin.yaml
```

Expected: line 383 is the `- name: notion_api_token` entry.

- [ ] **Step 2: Change the pattern**

In `internal/rules/builtin.yaml`, replace the `pattern:` line of the `notion_api_token` rule:

```diff
   - name: notion_api_token
     severity: HIGH
-    pattern: '\b(?:ntn|secret)_[a-zA-Z0-9\-_]{10,}\b'
+    pattern: '\b(?:ntn|secret)_[a-zA-Z0-9\-_]{40,}\b'
     tags: [notion, productivity]
```

- [ ] **Step 3: Rebuild syck**

```bash
go build -o $(go env GOPATH)/bin/syck .
```

Expected: no errors, exits 0.

- [ ] **Step 4: Re-run syck and check notion_api_token count dropped to 0**

```bash
syck scan /tmp/wrongsecrets --format json -o /tmp/syck-wrongsecrets-after-notion.json
python3 -c "
import json
d = json.load(open('/tmp/syck-wrongsecrets-after-notion.json'))['findings']
c = {}
for f in d:
    c[f['rule']] = c.get(f['rule'], 0) + 1
print('notion_api_token:', c.get('notion_api_token', 0))
"
```

Expected: `notion_api_token: 0`. If still > 0, the regex tightening is wrong — undo with `git checkout internal/rules/builtin.yaml` and stop, report failure.

- [ ] **Step 5: Verify no regression in other rules**

```bash
python3 -c "
import json
before = json.load(open('/tmp/syck-wrongsecrets-before.json'))['findings']
after = json.load(open('/tmp/syck-wrongsecrets-after-notion.json'))['findings']
b = {}
a = {}
for f in before: b[f['rule']] = b.get(f['rule'], 0) + 1
for f in after:  a[f['rule']] = a.get(f['rule'], 0) + 1
for r in sorted(set(b) | set(a)):
    if r == 'notion_api_token': continue  # we expect this to change
    if b.get(r, 0) != a.get(r, 0):
        print(f'REGRESSION: {r} {b.get(r,0)} -> {a.get(r,0)}')
print('done')
"
```

Expected: prints `done` and nothing else. Any `REGRESSION:` line means the change broke another rule.

- [ ] **Step 6: No commit (still part of the larger fix; commits happen in Task 5)**

---

## Task 3: Apply airtable_api_key exact-length + digit tightening

**Files:**
- Modify: `internal/rules/builtin.yaml:595` (the `pattern:` line of `airtable_api_key`)

- [ ] **Step 1: Change the pattern**

In `internal/rules/builtin.yaml`, replace the `pattern:` line of the `airtable_api_key` rule:

```diff
   - name: airtable_api_key
     severity: HIGH
-    pattern: '\bkey[A-Za-z0-9]{14,}\b'
+    pattern: '\bkey(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{14}\b'
     tags: [airtable, database]
```

- [ ] **Step 2: Rebuild syck**

```bash
go build -o $(go env GOPATH)/bin/syck .
```

Expected: no errors, exits 0.

- [ ] **Step 3: Re-run syck and check airtable_api_key count dropped to 0**

```bash
syck scan /tmp/wrongsecrets --format json -o /tmp/syck-wrongsecrets-after-airtable.json
python3 -c "
import json
d = json.load(open('/tmp/syck-wrongsecrets-after-airtable.json'))['findings']
c = {}
for f in d:
    c[f['rule']] = c.get(f['rule'], 0) + 1
print('airtable_api_key:', c.get('airtable_api_key', 0))
"
```

Expected: `airtable_api_key: 0`.

- [ ] **Step 4: Verify no regression in other rules (compare against the pre-airtable baseline from Task 2, not the original)**

```bash
python3 -c "
import json
before = json.load(open('/tmp/syck-wrongsecrets-after-notion.json'))['findings']
after  = json.load(open('/tmp/syck-wrongsecrets-after-airtable.json'))['findings']
b = {}
a = {}
for f in before: b[f['rule']] = b.get(f['rule'], 0) + 1
for f in after:  a[f['rule']] = a.get(f['rule'], 0) + 1
for r in sorted(set(b) | set(a)):
    if r == 'airtable_api_key': continue
    if b.get(r, 0) != a.get(r, 0):
        print(f'REGRESSION: {r} {b.get(r,0)} -> {a.get(r,0)}')
print('done')
"
```

Expected: prints `done`.

- [ ] **Step 5: No commit yet (consolidated in Task 5)**

---

## Task 4: Add jdbc: prefix to postgres_url, mysql_url, mongodb_url

**Files:**
- Modify: `internal/rules/builtin.yaml:633` (postgres_url pattern)
- Modify: `internal/rules/builtin.yaml:637` (mysql_url pattern)
- Modify: `internal/rules/builtin.yaml:641-643` (mongodb_url pattern)

- [ ] **Step 1: Update postgres_url**

In `internal/rules/builtin.yaml`, replace the `pattern:` line of the `postgres_url` rule:

```diff
   - name: postgres_url
     severity: HIGH
-    pattern: '\bpostgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+:\d+/[a-zA-Z0-9_]+\b'
+    pattern: '\b(?:jdbc:)?postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/[a-zA-Z0-9_?&=\-%.]*\b'
     tags: [database, postgres]
```

- [ ] **Step 2: Update mysql_url**

```diff
   - name: mysql_url
     severity: HIGH
-    pattern: '\bmysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/[a-zA-Z0-9_]*\b'
+    pattern: '\b(?:jdbc:)?mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/[a-zA-Z0-9_?&=\-%.]*\b'
     tags: [database, mysql]
```

- [ ] **Step 3: Update mongodb_url**

```diff
   - name: mongodb_url
     severity: MEDIUM
-    pattern: '\bmongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/?[a-zA-Z0-9_]*\b'
+    pattern: '\b(?:jdbc:)?mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/?[a-zA-Z0-9_?&=\-%.]*\b'
     tags: [database, mongodb]
```

- [ ] **Step 4: Rebuild syck**

```bash
go build -o $(go env GOPATH)/bin/syck .
```

Expected: no errors, exits 0.

- [ ] **Step 5: Re-run syck and check postgres_url jumped by 4 (the JDBC URLs)**

```bash
syck scan /tmp/wrongsecrets --format json -o /tmp/syck-wrongsecrets-after-jdbc.json
python3 -c "
import json
d = json.load(open('/tmp/syck-wrongsecrets-after-jdbc.json'))['findings']
c = {}
for f in d:
    c[f['rule']] = c.get(f['rule'], 0) + 1
for r in ['postgres_url', 'mysql_url', 'mongodb_url']:
    print(f'{r}: {c.get(r, 0)}')
"
```

Expected:
```
postgres_url: 4
mysql_url: 0
mongodb_url: 0
```

- [ ] **Step 6: Verify the 4 new postgres_url findings are the JDBC URLs**

```bash
python3 -c "
import json
d = json.load(open('/tmp/syck-wrongsecrets-after-jdbc.json'))['findings']
for f in d:
    if f['rule'] == 'postgres_url':
        print(f['file'], 'L', f['line'], '=>', f['secret'][:80])
"
```

Expected: 4 lines referencing JDBC URLs in `Challenge58.java`, `Challenge58Test.java`, `cursor/rules/project-specification.mdc`, and a hint file.

- [ ] **Step 7: Verify no regression in other rules (compare against the pre-JDBC baseline from Task 3)**

```bash
python3 -c "
import json
before = json.load(open('/tmp/syck-wrongsecrets-after-airtable.json'))['findings']
after  = json.load(open('/tmp/syck-wrongsecrets-after-jdbc.json'))['findings']
b = {}
a = {}
for f in before: b[f['rule']] = b.get(f['rule'], 0) + 1
for f in after:  a[f['rule']] = a.get(f['rule'], 0) + 1
for r in sorted(set(b) | set(a)):
    if r in ('postgres_url', 'mysql_url', 'mongodb_url'): continue
    if b.get(r, 0) != a.get(r, 0):
        print(f'REGRESSION: {r} {b.get(r,0)} -> {a.get(r,0)}')
print('done')
"
```

Expected: prints `done`.

- [ ] **Step 8: No commit yet (consolidated in Task 5)**

---

## Task 5: Final verification, commit, push

**Files:**
- Modify: `internal/rules/builtin.yaml` (already modified by Tasks 2-4)

- [ ] **Step 1: Run gofmt, go vet, and full test suite**

```bash
gofmt -l .       # expect no output
go vet ./...     # expect no output
go test ./...    # expect all packages PASS
```

If `gofmt -l .` lists any files, run `gofmt -w .` and re-stage.

If `go test ./...` reports any FAIL, investigate. None of the changed patterns affect unit tests, so a failure here would be unrelated to this work.

- [ ] **Step 2: Final consolidated diff vs. baseline**

```bash
python3 -c "
import json
before = json.load(open('/tmp/syck-wrongsecrets-before.json'))['findings']
after  = json.load(open('/tmp/syck-wrongsecrets-after-jdbc.json'))['findings']
b = {}
a = {}
for f in before: b[f['rule']] = b.get(f['rule'], 0) + 1
for f in after:  a[f['rule']] = a.get(f['rule'], 0) + 1
print(f'{\"rule\":30s} {\"before\":>8s} {\"after\":>8s} {\"delta\":>8s}')
print('-' * 56)
all_rules = sorted(set(b) | set(a))
for r in all_rules:
    bv, av = b.get(r, 0), a.get(r, 0)
    d = av - bv
    marker = '  ' if d == 0 else ('UP' if d > 0 else 'DN')
    print(f'{r:30s} {bv:>8d} {av:>8d} {d:>+8d}  {marker}')
"
```

Expected: `notion_api_token` 7→0 (DN), `airtable_api_key` 2→0 (DN), `postgres_url` 0→4 (UP), all other rules unchanged (no marker).

- [ ] **Step 3: Stage and commit the rule file change**

```bash
git diff internal/rules/builtin.yaml
git add internal/rules/builtin.yaml
git commit -m "$(cat <<'EOF'
fix: tighten notion_api_token and airtable_api_key, add jdbc: prefix to db URL rules

notion_api_token: require 40+ chars after prefix
  - was 10+, too short — matched Terraform resource names
  - real Notion tokens are 43 chars

airtable_api_key: require exactly 14 chars and at least one digit
  - was 14+, too loose — matched Java identifiers
  - real Airtable keys are 14 chars with digits

postgres_url/mysql_url/mongodb_url: accept jdbc: prefix
  - was missing jdbc:postgresql://, jdbc:mysql://, jdbc:mongodb://
  - now catches JDBC connection strings

Verified empirically: re-scanned /tmp/wrongsecrets/.
notion_api_token: 7->0, airtable_api_key: 2->0, postgres_url:
+4 JDBC URLs, mysql_url: +0, mongodb_url: +0. All other rule
counts unchanged.
EOF
)"
```

- [ ] **Step 4: Push to origin/main**

```bash
git push origin main
```

Expected: push succeeds, no GH013 (push protection) block. If blocked, follow the existing playbook (rename offending tokens, amend/rebase). The `paths-ignore` for `docs/superpowers/**` covers the spec file, but if any test fixture in this commit matches a pattern, it would have to be renamed.

- [ ] **Step 5: Confirm CI passes**

```bash
gh run list --limit 3
```

Expected: most recent CI run is `in_progress` or `success`. If it ends `failure`, the regex change broke a unit test — investigate, likely an over-broad match in test fixtures.

- [ ] **Step 6: Done**

Plan complete. The change is shipped as a single commit on `main`. No new tag needed unless the user wants to cut a V1.0.1 release.
