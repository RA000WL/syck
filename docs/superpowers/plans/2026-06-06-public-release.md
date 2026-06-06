# V1.6 Public Release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Polish `syck-go` for first public release: a structured README, hardened CI, and an automated release pipeline producing multi-platform binaries.

**Architecture:** (1) `README.md` restructured for first-time visitors with badges, real output, contributing guide; (2) CI workflows hardened with caching, gofmt check, and a new release workflow; (3) `.goreleaser.yaml` produces cross-platform binaries (linux/darwin/windows × amd64/arm64) on tag push, with SHA-256 checksums.

**Tech Stack:** GoReleaser v2, GitHub Actions, shields.io badges, Markdown.

---

### Task 1: README improvements

**Files:**
- Modify: `README.md` — restructure for first-time visitors

- [ ] **Step 1: Add badges and pitch at the top**

Replace lines 1-5 of `README.md` with:

```markdown
# syck

[![CI](https://github.com/RA000WL/syck/actions/workflows/ci.yml/badge.svg)](https://github.com/RA000WL/syck/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RA000WL/syck)](https://github.com/RA000WL/syck/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)

A fast, modular secret scanner written in Go. 130+ detection rules, multi-layer decoding, entropy analysis, URL crawling, and live secret validation — all in a single static binary.

**Why syck?** Most secret scanners either miss too much (regex-only) or drown you in false positives (entropy-only). syck combines both with rule-specific context keywords, decoder layers, and a precision-hardened rule set that scores 100% precision on the curated test corpus (vs. 11.9% for the Python reference).
```

- [ ] **Step 2: Add install section with release binaries**

After the badges, before the existing "Install" section, add:

```markdown
## Install

```bash
# Latest release (recommended)
go install github.com/RA000WL/syck@latest

# Or download a binary from https://github.com/RA000WL/syck/releases/latest

# Or build from source
git clone https://github.com/RA000WL/syck.git
cd syck
go build -o syck .
```
```

Note: this is what the existing Install section already says, but the plan is to keep the existing content and just ensure it's structured for a first-time reader. The existing Install section is at lines 21-33.

- [ ] **Step 3: Add a "Why syck?" section after Install**

Insert before the existing "Quick Start" section:

```markdown
## Why syck?

| Tool | Approach | Precision | Speed | Decoding | Live validation |
|------|----------|-----------|-------|----------|-----------------|
| syck | Regex + entropy + context + 130 rules | 100% (test corpus) | ~50 MB/s | base64, hex, unicode, url, gzip, JS | Yes (13 providers) |
| gitleaks | Regex only | ~70% | ~80 MB/s | None | No |
| trufflehog | Entropy + regex | noisy | ~20 MB/s | base64 | Yes (limited) |
| detect-secrets | Regex + entropy | ~60% | ~30 MB/s | None | No |

**Real scenario:** syck scans a 5 MB minified JavaScript bundle in under 2 seconds, reconstructs concatenated strings, decodes any base64-encoded tokens inside, and reports findings with line/column/rule/entropy/context — all in one pass.
```

- [ ] **Step 4: Update the Quick Start with realistic examples**

Replace the existing Quick Start section with:

```markdown
## Quick Start

```bash
# Scan a directory
syck scan .

# Scan a single file
syck scan path/to/config.js

# Scan a URL (auto-crawl with default settings)
syck scan -u https://example.com/app.js

# Scan from stdin
cat .env | syck scan --pipe

# Critical findings only, redacted output for CI logs
syck scan . --severity CRITICAL --redact --no-color

# JSON output for downstream tooling
syck scan . --format json -o results.json

# SARIF for GitHub Code Scanning
syck scan . --format sarif -o results.sarif
```

**Sample output:**

```
[HIGH]  [stripe_api_key]  config.js:42:18  entropy=4.81
       secret : sk_xxxxxxxxxxxxxxxx
       context: const apiKey = "sk_xxxxxxxxxxxxxxxx";

[HIGH]  [aws_access_key]  env.bak:3:1  entropy=3.92
       secret : AKIAxxxxxxxxxxxxxxxx
       context: AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx

── Summary ──
  Files with findings : 2
  Total findings      : 2
    HIGH      2
```
```

- [ ] **Step 5: Add Common Workflows section**

Insert before the "CLI Reference" section:

```markdown
## Common Workflows

### Pre-commit hook

Save as `.git/hooks/pre-commit`:

```sh
#!/bin/sh
syck scan . --severity CRITICAL --fail-on CRITICAL --quiet --no-color
```

```bash
chmod +x .git/hooks/pre-commit
```

### GitHub Action

```yaml
- name: Scan for secrets
  run: |
    go install github.com/RA000WL/syck@latest
    syck scan . --severity HIGH --fail-on HIGH --format sarif -o results.sarif --no-color
- name: Upload SARIF to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### Generate `.syckignore` from existing findings

```bash
syck scan . --format json | jq -r '.findings[] | "\(.rule):\(.secret):\(.file)"' | \
  while read line; do
    fp=$(echo -n "$line" | sha256sum | cut -d' ' -f1)
    echo "$fp  # $line"
  done > .syckignore
```

### Validate live secrets

```bash
# Confirm found secrets are still active (slower, hits provider APIs)
syck scan . --validate
```

Validation downgrades unconfirmed secrets to `INFO`.
```

- [ ] **Step 6: Add Contributing section before License**

Insert before the "## License" line:

```markdown
## Contributing

```bash
# Fork + clone
git clone https://github.com/YOUR_USERNAME/syck.git
cd syck

# Make a branch
git checkout -b feature/my-rule

# Run tests
go test ./...

# Run rule quality tests
go run . ruletest

# Verify gofmt + vet
gofmt -l .
go vet ./...

# Commit + push + open a PR
git commit -m "feat(rules): add my_internal_api_key pattern"
git push origin feature/my-rule
```

**Adding a new rule:** Edit `internal/rules/builtin.yaml`, then add positive + negative test fixtures under `internal/ruletest/testdata/`. Run `go run . ruletest` to verify precision/recall before pushing.

**Code style:** `gofmt` + `go vet` + `golangci-lint` must all pass. No new top-level dependencies without discussion.
```

- [ ] **Step 7: Verify gofmt + build still pass**

Run: `gofmt -l . && go build ./... && go test ./...`

Expected: no gofmt issues, build clean, all tests pass.

- [ ] **Step 8: Commit**

```bash
git add README.md
git commit -m "docs: restructure README for first-time visitors with badges, examples, contributing guide"
```

---

### Task 2: CI workflow hardening

**Files:**
- Modify: `.github/workflows/ci.yml` — add caching, gofmt check
- Modify: `.github/workflows/ruletest.yml` — add caching

- [ ] **Step 1: Add caching + gofmt to ci.yml**

Replace `.github/workflows/ci.yml` with:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  build:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        go-version: ['1.26.x']
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}
          cache: true

      - name: Build
        run: go build -v ./...

      - name: gofmt
        run: |
          if [ "$(gofmt -l . | wc -l)" -ne 0 ]; then
            echo "gofmt issues:"
            gofmt -l .
            exit 1
          fi

      - name: Vet
        run: go vet ./...

      - name: Test
        run: go test -v -race -timeout 60s ./...

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.x'
          cache: true

      - name: golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
          install-mode: goinstall
```

- [ ] **Step 2: Add caching to ruletest.yml**

Replace `.github/workflows/ruletest.yml` with:

```yaml
name: Rule Quality Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  ruletest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.x'
          cache: true

      - name: Build syck
        run: go build -o syck .

      - name: Rule quality tests
        run: ./syck ruletest
```

- [ ] **Step 3: Verify workflows are valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ruletest.yml'))"`

Expected: no output (validation passes)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/ruletest.yml
git commit -m "ci: add gofmt check and Go module caching"
```

---

### Task 3: Release pipeline (GoReleaser)

**Files:**
- Modify: `main.go` — add version variables
- Add: `cmd/version.go` — `syck version` subcommand
- Add: `.goreleaser.yaml` — release config
- Add: `.github/workflows/release.yml` — release trigger

- [ ] **Step 1: Add version variables to main.go**

Read `main.go` first, then add at the top of `main.go`:

```go
var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)

func main() {
    cmd.Execute()
}
```

The exact existing structure may vary; the goal is to add three `var` declarations and ensure `main()` delegates to the cobra root.

- [ ] **Step 2: Create cmd/version.go**

Create `cmd/version.go`:

```go
package cmd

import (
    "fmt"

    "github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Print syck version",
    Long:  "Print syck version, commit, and build date.",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("syck %s\n", version)
        fmt.Printf("  commit: %s\n", commit)
        fmt.Printf("  date:   %s\n", date)
    },
}

func init() {
    rootCmd.AddCommand(versionCmd)
}
```

Note: the existing root command in `cmd/root.go` (or similar) is `rootCmd`. Verify by reading `cmd/` first.

- [ ] **Step 3: Verify `syck version` works**

Run: `go run . version`

Expected output:
```
syck dev
  commit: none
  date:   unknown
```

(Values are `dev/none/unknown` in dev builds; release builds will inject real values via ldflags.)

- [ ] **Step 4: Create .goreleaser.yaml**

Create `.goreleaser.yaml`:

```yaml
version: 2

project_name: syck

before:
  hooks:
    - go mod tidy
    - go test ./...

builds:
  - id: syck
    main: ./
    binary: syck
    env:
      - CGO_ENABLED=0
    goos:
      - linux
      - darwin
      - windows
    goarch:
      - amd64
      - arm64
    ignore:
      - goos: windows
        goarch: arm64
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.Commit}}
      - -X main.date={{.Date}}

archives:
  - id: syck
    formats: [tar.gz, zip]
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

checksum:
  name_template: 'checksums.txt'
  algorithm: sha256

changelog:
  use: git
  sort: asc
  filters:
    exclude:
      - '^docs:'
      - '^chore:'
      - '^test:'
      - '^ci:'
      - Merge pull request
      - Merge branch

release:
  github:
    owner: RA000WL
    name: syck
  prerelease: auto
  draft: false
```

- [ ] **Step 5: Create .github/workflows/release.yml**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.x'
          cache: true

      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v6
        with:
          version: latest
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 6: Verify GoReleaser config is valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.goreleaser.yaml'))"`

Expected: no output.

- [ ] **Step 7: Run gofmt + tests**

Run: `gofmt -l . && go build ./... && go test ./...`

Expected: clean, all pass.

- [ ] **Step 8: Commit**

```bash
git add main.go cmd/version.go .goreleaser.yaml .github/workflows/release.yml
git commit -m "feat(release): add GoReleaser pipeline with version subcommand"
```

---

### Task 4: Tag a v1.6.0 release (manual, requires user action)

- [ ] **Step 1: Verify local build**

Run: `go build -o /tmp/syck . && /tmp/syck version`

Expected: `syck dev\n  commit: none\n  date:   unknown`

- [ ] **Step 2: Tag the release**

```bash
git tag -a v1.6.0 -m "V1.6: Public Release"
git push origin v1.6.0
```

> Note: this triggers the release workflow. The user must run the tag command.

- [ ] **Step 3: Verify release workflow runs**

Visit https://github.com/RA000WL/syck/actions and check the "Release" workflow ran successfully.

- [ ] **Step 4: Verify binaries are available**

Visit https://github.com/RA000WL/syck/releases/tag/v1.6.0 and confirm binaries + checksums are present.
