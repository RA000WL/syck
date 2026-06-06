# V1.7 Operational Polish — Design Spec

**Goal:** Make `syck-go` easier to integrate into CI/CD pipelines, container environments, and long-running scans.

**Architecture:** (1) All CLI flags become settable via `SYCK_<CMD>_<FLAG>` env vars for container/CI use; (2) `--progress` shows a real-time TUI progress bar during scans; (3) GitHub Code Scanning upload documented and validated.

**Tech Stack:** stdlib `os` for env, github.com/schollz/progressbar/v3 for TUI.

---

## Problem Statement

Current `syck-go` works well for local scans but has friction in operational contexts:

1. **Container/CI users** must wrap every flag in shell scripts. Env vars (`SYCK_SCAN_SEVERITY=HIGH`) are the standard pattern.
2. **Long scans** show no progress. A 5-minute scan on a large repo gives the user no signal.
3. **SARIF upload** to GitHub Code Scanning works but the workflow isn't documented in-repo.

## Design

### Task 1: Env var config (`SYCK_*`)

All `syck scan` flags become overridable via env vars using the convention `SYCK_SCAN_<FLAG>`:

| Flag | Env var |
|------|---------|
| `--severity` | `SYCK_SCAN_SEVERITY` |
| `--format` | `SYCK_SCAN_FORMAT` |
| `--output` | `SYCK_SCAN_OUTPUT` |
| `--redact` | `SYCK_SCAN_REDACT` |
| `--no-dedup` | `SYCK_SCAN_NO_DEDUP` |
| `--workers` | `SYCK_SCAN_WORKERS` |
| `--max-file-size` | `SYCK_SCAN_MAX_FILE_SIZE` |
| ... | ... |

Implementation: After `cobra` parses flags, check `os.Getenv` for each flag's env var. Env var wins if set AND non-empty. Flag wins over env var. Default wins over nothing.

Use `viper.BindEnv` for declarative binding.

**Example:**
```bash
export SYCK_SCAN_SEVERITY=CRITICAL
export SYCK_SCAN_FORMAT=json
export SYCK_SCAN_OUTPUT=results.json
syck scan .  # picks up env vars
```

### Task 2: `--progress` TUI progress bar

Add `--progress` flag. When enabled, show a progress bar with:
- Current file being scanned
- Number of files scanned / total
- Number of findings so far
- ETA

Use `github.com/schollz/progressbar/v3` for the bar component. Update bar in scanner worker goroutine via a thread-safe counter.

**Behavior:**
- Default: no progress bar (silent mode preserved)
- `--progress`: shows bar on stderr
- `--quiet`: overrides `--progress` (silent wins)
- Auto-disabled when `--pipe` is set (no TTY)

### Task 3: SARIF upload docs

Already have `--format sarif` and the GitHub Action example in README. Improvements:

1. Add a `syck upload-sarif` subcommand that uses the GitHub API directly (no need for `github/codeql-action`)
2. Add a working example in `docs/examples/github-actions.yml`
3. Test the upload flow with a dummy file

**`syck upload-sarif`:**
```bash
syck upload-sarif --file results.sarif --repo OWNER/REPO --token $GITHUB_TOKEN
```

Uses the GitHub Code Scanning API: `POST /repos/{owner}/{repo}/code-scanning/sarifs`.

## Constraints

- No new top-level dependencies for env config (stdlib only)
- One new top-level dependency: `progressbar/v3` (small, well-maintained)
- All tests must pass; CI must remain green
- Backward compatible: all new flags default to off

## Out of scope

- Webhook dispatch (deferred — not needed)
- SARIFv3 (sticking with 2.1.0 for now)
- Multiple GitHub repos per scan
