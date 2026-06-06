# V1.6 Public Release — Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `syck-go` ready for public release with a polished README, verified CI, and an automated release pipeline producing multi-platform binaries.

**Architecture:** (1) README restructured with badges, real output examples, comparison pitch, and a contributing guide; (2) CI workflows hardened with secret scanning, caching, and matrix coverage; (3) GoReleaser config produces cross-platform binaries (linux/darwin/windows × amd64/arm64) on tag push, with SHA-256 checksums and a Homebrew tap recipe.

**Tech Stack:** GoReleaser v2 (Go-based, single binary), GitHub Actions (existing), shields.io badges (static), Markdown.

---

## Problem Statement

The current `syck-go` repo has all V1-V1.5 features complete but lacks the polish needed for first-time-user adoption:

1. **README** is 259 lines of feature list + flag tables but lacks a concrete "why syck?" pitch, real output examples, badges, and a contributing guide. A new visitor can't tell in 10 seconds whether to use it.

2. **CI** has a working `ci.yml` and `ruletest.yml` but no GoReleaser pipeline, no release artifacts, no SHA-256 checksums, and no release workflow. Users must `go install` from source, which is a barrier for non-Go developers.

3. **Release pipeline** does not exist. Every release requires manual `go build` on each platform.

## Design

### Task 1: README improvements

Restructure `README.md` for first-time visitors:

**Top of file** (within 5 lines users see):
- Title + one-line pitch
- CI status badge (shields.io)
- Latest release badge
- License badge
- Go version badge
- "go install" command

**Section 1: Why syck?** (new)
- Comparison: gitleaks (regex-only, 90% precision on test corpora), trufflehog (noisy, slow), syck (regex + entropy + 130 rules + multi-format decoding + live validation)
- One concrete scenario: "Find a leaked AWS key in a 5MB minified JS bundle in under 2 seconds"

**Section 2: Quick start** (replace current)
- 5 commands: scan dir, scan URL, scan from stdin, output JSON, exit-code CI mode
- Real sample output (truncated, colorized)

**Section 3: Output samples** (new)
- Real findings table with 3 examples (Stripe, AWS, GitHub PAT)
- Each example shows rule, severity, line, context, entropy

**Section 4: Common workflows** (new)
- Pre-commit hook
- GitHub Action step
- Slack/Discord alert via webhook (when --webhook-url lands in V1.7)
- Generate `.syckignore` from findings

**Section 5: CLI reference** (existing, keep)
- Same flag tables as before, but grouped more logically

**Section 6: Architecture** (existing, keep)

**Section 7: Contributing** (new)
- Fork → branch → test → PR
- Code style (gofmt, golangci-lint)
- Rule contribution workflow
- Run `syck ruletest` before pushing

**Section 8: License** (existing)

### Task 2: CI workflow hardening

Existing workflows are functional. Improvements:

**`ci.yml`:**
- Add `actions/setup-go@v5` cache mode for faster runs
- Add `gofmt -l .` step
- Add `gocover` or similar coverage report (optional, can be skipped)
- Keep multi-OS matrix

**`ruletest.yml`:**
- Already minimal. Add caching and pin `syck` build artifact for downstream use.

**New: `release.yml`:**
- Triggered on `v*` tag push
- Runs GoReleaser (uses `goreleaser/goreleaser-action@v6`)
- Publishes GitHub Release with binaries + checksums
- Permissions: `contents: write` (release), `id-token: write` (cosign optional)

**New: `secret-scan.yml`:** (optional)
- Run gitleaks on every PR to catch secrets before merge
- Catches what GitHub's built-in push protection might miss

### Task 3: GoReleaser config

`.goreleaser.yaml` at repo root:

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

**Required: ldflags variables**

`main.go` currently has no version variable. Add:
```go
var (
    version = "dev"
    commit  = "none"
    date    = "unknown"
)
```

`./syck --version` and `./syck version` (new subcommand) print these.

## Constraints

- No new top-level dependencies (GoReleaser runs in CI, not in the binary)
- Existing CI must continue to pass
- README length: keep under 400 lines (avoid bloat)
- All examples must be runnable (test in CI? optional, low priority)

## Out of scope

- Homebrew tap (separate repo needed)
- Docker image (multi-arch Docker is its own project)
- VS Code extension
- Web UI
- Real-time collaboration features
