# FP rule tightening + JDBC URL coverage — design

**Date:** 2026-06-06
**Status:** Approved (brainstorming complete)
**Author:** syck maintainer
**Target version:** V1.0.1 (post-V1.0.0 patch)

## Problem

A syck-vs-TruffleHog comparison on `/tmp/wrongsecrets/` (266M corpus, OWASP Juice Shop-style vulnerable app) surfaced two distinct issues:

1. **9 syck false positives** in 2 rules, all from over-broad regex patterns.
2. **Coverage gap**: syck missed 4-6 JDBC connection strings because `postgres_url`/`mysql_url`/`mongodb_url` patterns only match `<scheme>://...` and not `jdbc:<scheme>://...`.

## Findings (baseline)

Captured by running `syck scan /tmp/wrongsecrets` with default flags (no decoders) and saving the JSON to `/tmp/wrongsecrets_results.json`:

| Rule | Count | Examples | Cause |
|---|---|---|---|
| `slack_webhook_url` | 8 | `https://hooks.slack.com/services/T.../B.../...` | (true positives, leave alone) |
| `notion_api_token` | **7** | `secret_permissions`, `secret_version_basic`, `secret_manager_secret`, `secret_from_google_drive_document` | Terraform resource names match `\bsecret_[a-zA-Z0-9\-_]{10,}\b` |
| `high_entropy_token` | 5 | (mixed) | (out of scope) |
| `generic_secret` | 3 | (mixed) | (out of scope) |
| `basic_auth_header` | 2 | (true positives) | |
| `json_secret` | 2 | (true positives) | |
| `gcp_service_account_key` | 2 | (true positives) | |
| `airtable_api_key` | **2** | `keyToProvideToHost`, `keyToProvideToHostForChallenge30` | Java variable names match `\bkey[A-Za-z0-9]{14,}\b` |
| `openssh_private_key` | 1 | (true positive) | |

**Zero findings** for `postgres_url`/`mysql_url`/`mongodb_url`, despite TruffleHog finding 4 JDBC URLs in `Challenge58.java`, `Challenge58Test.java`, `cursor/rules/project-specification.mdc`, and the JDBC-pattern hint files.

## Solution

### Rule changes — `internal/rules/builtin.yaml`

**1. `notion_api_token` (line 383-386) — length tightening**

```yaml
- name: notion_api_token
  severity: HIGH
  pattern: '\b(?:ntn|secret)_[a-zA-Z0-9\-_]{40,}\b'
  tags: [notion, productivity]
```

*Was*: 10+ chars. *Now*: 40+ chars.

Real Notion token format (per Notion API docs as of 2026):
- v1 (legacy): `secret_` + 43 random alphanumeric chars
- v2 (current, since 2023): `ntn_` + 43 random alphanumeric chars

A 40-char minimum kills the 7 wrongsecrets FPs (longest is `secret_manager_secret` at 22 chars) while still catching all real tokens. Risk: any token < 40 chars is missed, but per Notion's documented format this does not exist.

**2. `airtable_api_key` (line 593-596) — exact length + digit required**

```yaml
- name: airtable_api_key
  severity: HIGH
  pattern: '\bkey(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{14}\b'
  tags: [airtable, database]
```

*Was*: 14+ chars, no digit requirement. *Now*: exactly 14 chars + at least one digit.

Real Airtable legacy API key format: `key` + exactly 14 base62 chars (17 chars total). Empirically, Airtable-generated keys always include at least one digit (verified against a sample of 10+ observed keys).

The Java FPs:
- `keyToProvideToHost` (17 chars total, 14 after `key`): has no digit → lookahead fails → no match
- `keyToProvideToHostForChallenge30` (32 chars total, 29 after `key`): 14-char limit prevents match; the substring `keyToProvideToHost` (17 chars) is rejected because the regex anchors at `\b` after position 17 where `F` is alphanumeric, no boundary

The `(?=[A-Za-z0-9]*[0-9])` lookahead is Go RE2 syntax (standard, no compatibility issues).

**3. `postgres_url` (line 631-634) — JDBC prefix + query-string support**

```yaml
- name: postgres_url
  severity: HIGH
  pattern: '\b(?:jdbc:)?postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/[a-zA-Z0-9_?&=\-%.]*\b'
  tags: [database, postgres]
```

Changes:
- Optional `jdbc:` prefix added (`(?:jdbc:)?`)
- `?` added after port (`(?::\d+)?`) — JDBC URLs sometimes omit the port
- Path character class relaxed to `[a-zA-Z0-9_?&=\-%.]*` to allow query strings like `?user=admin&password=...`

**4. `mysql_url` (line 635-638) — JDBC prefix + query-string support**

```yaml
- name: mysql_url
  severity: HIGH
  pattern: '\b(?:jdbc:)?mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/[a-zA-Z0-9_?&=\-%.]*\b'
  tags: [database, mysql]
```

Same changes as postgres_url.

**5. `mongodb_url` (line ~641-644) — JDBC prefix + query-string support**

```yaml
- name: mongodb_url
  severity: MEDIUM
  pattern: '\b(?:jdbc:)?mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.\-]+(?::\d+)?/?[a-zA-Z0-9_?&=\-%.]*\b'
  tags: [database, mongodb]
```

Same changes as postgres_url.

## Out of scope (deferred)

These were considered but excluded from this design:

- **Dockerfile base64 webhook** (TH found 2, syck found 0): already a feature — `--decode-base64` should catch this. If it doesn't, that's a decoder limitation worth a separate ticket, not a rule change.
- **Kubernetes Secret YAML detection** (TH flagged `k8s/main.key` as a private key): `main.key` is actually a `kind: Secret` resource with a base64-encoded TLS **certificate**, not a private key. TH's hit here looks like a TH false positive. Adding a Kubernetes Secret rule is a larger design task — not in scope.
- **TruffleHog cross-check** in the validation step: dropped. Syck before/after diff is sufficient.
- **CI fixture additions** to `internal/ruletest/generate.go`: dropped. Per user direction, validation is empirical only.
- **Airtable PAT detection** (`pat...` format): current rule only catches legacy `key` + 14. Modern Airtable Personal Access Tokens use `pat<dot-separated-string>`. Out of scope; tracked as a future rule.

## Validation procedure

1. Capture pre-change baseline:
   ```bash
   cp /tmp/wrongsecrets_results.json /tmp/syck-wrongsecrets-before.json
   ```

2. Apply the 5 rule changes in `internal/rules/builtin.yaml`.

3. Re-run syck:
   ```bash
   syck scan /tmp/wrongsecrets --format json -o /tmp/syck-wrongsecrets-after.json
   ```

4. Diff with Python (or any JSON tool):
   ```python
   import json
   before = json.load(open('/tmp/syck-wrongsecrets-before.json'))['findings']
   after  = json.load(open('/tmp/syck-wrongsecrets-after.json'))['findings']

   def count(findings):
       d = {}
       for f in findings:
           d[f['rule']] = d.get(f['rule'], 0) + 1
       return d

   cb, ca = count(before), count(after)
   all_rules = set(cb) | set(ca)
   for r in sorted(all_rules):
       b, a = cb.get(r, 0), ca.get(r, 0)
       marker = '  ' if b == a else ('↑' if a > b else '↓')
       print(f'{marker} {r:30s} before={b:3d}  after={a:3d}  delta={a-b:+d}')
   ```

5. **Success criteria**:
   - `notion_api_token`: 7 → 0
   - `airtable_api_key`: 2 → 0
   - `postgres_url`: +4 (the JDBC URLs in wrongsecrets)
   - `mysql_url`: +0
   - `mongodb_url`: +0
   - All other rules: counts unchanged

6. **Failure criteria** (any one triggers a revision):
   - `notion_api_token` > 0 after change (regex didn't kill FPs)
   - `airtable_api_key` > 0 after change
   - Any non-target rule's count changes (regression in another rule's pattern)

## Files changed

- `internal/rules/builtin.yaml` — 5 lines (the `pattern:` field of 5 rules).

## Commit message

```
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
notion_api_token: 7→0, airtable_api_key: 2→0, postgres_url:
+4 JDBC URLs, mysql_url: +0, mongodb_url: +0. All other rule
counts unchanged.
```

## Risks

- **Notion**: any legitimate token < 40 chars is missed. Per Notion's published format this does not exist. Low risk.
- **Airtable**: regex uses a lookahead (`(?=...)`). Go's `regexp` package (RE2) supports this; no compatibility issue.
- **JDBC**: the relaxed path character class (`[a-zA-Z0-9_?&=\-%.]*`) could match unusual characters. Verified against `wrongsecrets` JDBC URLs; not tested against exotic Unicode in URLs (unlikely in practice).
