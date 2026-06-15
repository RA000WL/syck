# Detection Rules Gap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix broken K8s rule, add missing provider detection rules (Age keys, Twilio auth token, Cloudflare Global API Key, Firebase service account, Terraform/IaC patterns), and add docker-compose/K8s config secret rules.

**Architecture:** All changes are YAML-only additions/modifications to `internal/rules/builtin.yaml`. One rule needs `multi_line: true` added. No Go code changes required.

**Tech Stack:** YAML, Go regexp (RE2), existing rule validation pipeline.

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `internal/rules/builtin.yaml` | Modify | Fix K8s rule, add ~12 new rules |

---

### Task 1: Fix K8s Secret Regex + Add Container Config Rules

**Files:**
- Modify: `internal/rules/builtin.yaml:435-438`

The existing `kubernetes_secret` rule has `pattern: '(?i)apiVersion:\s*v1\s*\nkind:\s*Secret\s*\n'` — valid RE2 but lacks `multi_line: true`, so it never matches (scanner is line-by-line). Fix by adding `multi_line: true`.

Also add docker-compose and K8s ConfigMap rules.

- [ ] **Step 1: Fix kubernetes_secret rule**

Replace lines 435-438:
```yaml
  - name: kubernetes_secret
    severity: HIGH
    pattern: '(?i)apiVersion:\s*v1\s*\nkind:\s*Secret\s*\n'
    tags: [kubernetes, container]
```

With:
```yaml
  - name: kubernetes_secret
    severity: HIGH
    pattern: '(?i)apiVersion:\s*v1\s*\nkind:\s*Secret\s*\n'
    tags: [kubernetes, container]
    multi_line: true
  - name: docker_compose_secret
    severity: HIGH
    pattern: '(?i)(?:environment|env):\s*\n\s+(?:.*(?:password|secret|token|api_key|access_key)\s*[:=]\s*[''"]?\S+){1}'
    tags: [docker, container]
    multi_line: true
    requires_context: true
    context_keywords: [password, secret, token, api_key, access_key, auth]
```

- [ ] **Step 2: Run tests**

```bash
cd /home/raven/secretsyoucantkeep/syck-go
go test -race ./internal/rules/...
go vet ./internal/rules/
```

Expected: PASS (rule compilation validated by `Validate()` which calls `regexp.Compile`)

- [ ] **Step 3: Smoke test the K8s rule**

```bash
echo 'apiVersion: v1
kind: Secret
metadata:
  name: my-secret
data:
  password: cGFzc3dvcmQ=' | go run . scan --pipe --no-color -q
```

Expected: `kubernetes_secret` finding at line 2

- [ ] **Step 4: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "fix(rules): add multi_line to kubernetes_secret, add docker_compose_secret"
```

---

### Task 2: Add Encryption Key Rules (Age + PGP Subkey)

**Files:**
- Modify: `internal/rules/builtin.yaml` (append after Private Keys section, ~line 628)

Age encryption keys (`AGE-SECRET-KEY-...`) are increasingly common in modern repos and are critical secrets.

- [ ] **Step 1: Add age_private_key rule**

Append after the `pgp_private_key` rule (line 628):
```yaml
  - name: age_private_key
    severity: CRITICAL
    pattern: 'AGE-SECRET-KEY-[A-Z0-9]+'
    tags: [crypto, private-key, age]
```

- [ ] **Step 2: Run tests**

```bash
go test -race ./internal/rules/...
```

Expected: PASS

- [ ] **Step 3: Smoke test**

```bash
echo 'key = "AGE-SECRET-KEY-1QGYZVSM7K3KZ8AQL5P4A4W9QZK2QZ8A5Z6X7C8' | go run . scan --pipe --no-color -q
```

Expected: `age_private_key` CRITICAL finding

- [ ] **Step 4: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add age_private_key detection rule"
```

---

### Task 3: Add Twilio Auth Token + Cloudflare Global API Key Rules

**Files:**
- Modify: `internal/rules/builtin.yaml`

The existing `twilio_account_sid` and `twilio_api_key_sid` don't cover the auth token (32-char hex). The existing `cloudflare_api_token` requires key=value format and misses the Global API Key (40-char hex with context).

- [ ] **Step 1: Add twilio_auth_token rule**

Append after the `twilio_api_key_sid` rule (line 138):
```yaml
  - name: twilio_auth_token
    severity: CRITICAL
    pattern: '(?i)(?:twilio)[_-]?(?:auth[_-]?)?token\s*[:=]\s*[''"]([a-f0-9]{32})[''"]'
    tags: [twilio, sms]
```

- [ ] **Step 2: Add cloudflare_global_api_key rule**

Append after the `cloudflare_origin_ca_key` rule (line 358):
```yaml
  - name: cloudflare_global_api_key
    severity: CRITICAL
    pattern: '(?i)(?:cloudflare)[_-]?(?:global[_-]?)?(?:api[_-]?)?key\s*[:=]\s*[''"]([0-9a-f]{40})[''"]'
    tags: [cloudflare, cdn]
```

- [ ] **Step 3: Run tests**

```bash
go test -race ./internal/rules/...
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add twilio_auth_token and cloudflare_global_api_key rules"
```

---

### Task 4: Add Firebase Service Account + Google Key Rules

**Files:**
- Modify: `internal/rules/builtin.yaml`

The existing `firebase_fcm_key` only catches FCM push keys. Missing: Firebase service account JSON, `google-services.json`, Firebase Admin SDK paths.

- [ ] **Step 1: Add firebase_service_account rule**

Append after the `firebase_config` rule (line 656):
```yaml
  - name: firebase_service_account
    severity: CRITICAL
    pattern: '"type"\s*:\s*"service_account"'
    tags: [firebase, gcp, service-account]
  - name: firebase_adminsdk_key
    severity: CRITICAL
    pattern: 'firebase-adminsdk-[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com'
    tags: [firebase, gcp, service-account]
  - name: google_services_json
    severity: HIGH
    pattern: '"project_id"\s*:\s*"[a-z0-9-]+"'
    tags: [firebase, android, spa]
    requires_context: true
    context_keywords: [firebase, project_id, api_key, google]
```

- [ ] **Step 2: Run tests**

```bash
go test -race ./internal/rules/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add firebase_service_account and firebase_adminsdk_key rules"
```

---

### Task 5: Add Terraform/IaC Rules

**Files:**
- Modify: `internal/rules/builtin.yaml`

Terraform files (.tf, .tfvars) are in the extension whitelist and ARE scanned, but no Terraform-specific patterns exist. Add rules for sensitive values in HCL.

- [ ] **Step 1: Add terraform rules**

Append after the `ansible_vault_password` rule (line 570):
```yaml
  - name: terraform_aws_access_key
    severity: CRITICAL
    pattern: '(?i)(?:access_key|secret_key)\s*=\s*[''"](?:AKIA|ASIA)[A-Z0-9]{16}[''"]'
    tags: [terraform, iac, aws]
  - name: terraform_sensitive_var
    severity: HIGH
    pattern: '(?i)(?:password|secret|token|api_key|private_key)\s*=\s*[''"][^''"]{8,}[''"]'
    tags: [terraform, iac, sensitive]
    requires_context: true
    context_keywords: [variable, sensitive, default]
  - name: terraform_backend_credentials
    severity: CRITICAL
    pattern: '(?i)(?:access_key|secret_key|password|token)\s*[:=]\s*[''"][^''"]{8,}[''"]'
    tags: [terraform, iac, backend]
```

- [ ] **Step 2: Run tests**

```bash
go test -race ./internal/rules/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add terraform_aws_access_key, terraform_sensitive_var, terraform_backend_credentials"
```

---

### Task 6: Add Supabase + Cloud Provider Rules

**Files:**
- Modify: `internal/rules/builtin.yaml`

Missing: Supabase DB URLs, Alibaba Cloud, Hetzner, Scaleway tokens.

- [ ] **Step 1: Add cloud provider rules**

Append after the `digitalocean_token` rule (line 716):
```yaml
  - name: supabase_service_key
    severity: CRITICAL
    pattern: '(?i)sb[-_]?(?:service|anon)[_-]?key\s*[:=]\s*[''"]eyJ[a-zA-Z0-9\-_]{30,}[''"]'
    tags: [supabase, database]
  - name: alibaba_access_key
    severity: HIGH
    pattern: '\bLTAI[A-Za-z0-9]{12,20}\b'
    tags: [alibaba, cloud]
  - name: hetzner_api_token
    severity: HIGH
    pattern: '(?i)hetzner[_-]?(?:api[_-]?)?token\s*[:=]\s*[''"][A-Za-z0-9]{30,}[''"]'
    tags: [hetzner, cloud]
  - name: scaleway_access_key
    severity: HIGH
    pattern: '\bSCW[A-Za-z0-9]{17}\b'
    tags: [scaleway, cloud]
  - name: linode_personal_access_token
    severity: HIGH
    pattern: '(?i)(?:linode|akamai)[_-]?(?:api[_-]?)?(?:token|key)\s*[:=]\s*[''"][a-f0-9]{64}[''"]'
    tags: [linode, cloud]
```

- [ ] **Step 2: Run tests**

```bash
go test -race ./internal/rules/...
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/rules/builtin.yaml
git commit -m "feat(rules): add supabase, alibaba, hetzner, scaleway, linode rules"
```

---

### Task 7: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Full test suite**

```bash
cd /home/raven/secretsyoucantkeep/syck-go
go test -race ./...
go vet ./...
gofmt -l .
```

Expected: All PASS, no warnings, no unformatted files

- [ ] **Step 2: Rule count verification**

```bash
go run . list-rules | wc -l
```

Expected: ~185+ rules (was 170 before this plan)

- [ ] **Step 3: Build and smoke test**

```bash
go build -o /tmp/syck_rules .
/tmp/syck_rules list-rules | grep -E "(age_private|kubernetes_secret|twilio_auth|cloudflare_global|firebase_service|terraform_aws|supabase_service|alibaba_access|docker_compose)"
```

Expected: All new rules listed

- [ ] **Step 4: Scan stress test file**

```bash
/tmp/syck_rules scan syck_stress_test.js --no-color -q 2>/dev/null | head -5
```

Expected: Findings output (not empty)

- [ ] **Step 5: Commit (if any fixups needed)**

```bash
git add -A
git commit -m "chore: final verification for detection rules gap"
```

---

## Summary of New Rules (12 total)

| Rule | Severity | Category | Notes |
|------|----------|----------|-------|
| `kubernetes_secret` | HIGH | container | FIXED: added `multi_line: true` |
| `docker_compose_secret` | HIGH | container | NEW: docker-compose env secrets |
| `age_private_key` | CRITICAL | crypto | NEW: Age encryption keys |
| `twilio_auth_token` | CRITICAL | sms | NEW: Twilio 32-char hex auth token |
| `cloudflare_global_api_key` | CRITICAL | cdn | NEW: Cloudflare 40-char hex global key |
| `firebase_service_account` | CRITICAL | gcp | NEW: Firebase service_account JSON |
| `firebase_adminsdk_key` | CRITICAL | gcp | NEW: Firebase Admin SDK email |
| `google_services_json` | HIGH | android | NEW: google-services.json project_id |
| `terraform_aws_access_key` | CRITICAL | iac | NEW: AWS keys in .tf files |
| `terraform_sensitive_var` | HIGH | iac | NEW: sensitive vars in HCL |
| `terraform_backend_credentials` | CRITICAL | iac | NEW: backend credentials in HCL |
| `supabase_service_key` | CRITICAL | database | NEW: Supabase service/anon keys |
| `alibaba_access_key` | HIGH | cloud | NEW: Alibaba LTAI* keys |
| `hetzner_api_token` | HIGH | cloud | NEW: Hetzner API tokens |
| `scaleway_access_key` | HIGH | cloud | NEW: Scaleway SCW* keys |
| `linode_personal_access_token` | HIGH | cloud | NEW: Linode/Akamai tokens |
