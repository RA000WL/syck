# V1.7 Operational Polish — Implementation Plan

> **For agentic workers:** Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `syck-go` easier to integrate into CI/CD pipelines, container environments, and long-running scans.

---

### Task 1: Env var config (`SYCK_*`)

**Files:**
- Modify: `cmd/scan.go` — bind env vars to all flags

- [ ] **Step 1: Add viper.BindEnv calls after flag registration**

In `cmd/scan.go` `init()`, after the existing flag registrations, add a single call to a new helper:

```go
bindEnvToFlags(scanCmd)
```

- [ ] **Step 2: Create cmd/env.go with the helper**

```go
package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func bindEnvToFlags(cmd *cobra.Command) {
	prefix := "SYCK_" + strings.ToUpper(cmd.Name()) + "_"
	_ = cmd.Flags().VisitAll(func(f *cobra.Flag) {
		envKey := prefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if val, ok := os.LookupEnv(envKey); ok && val != "" {
			_ = cmd.Flags().Set(f.Name, val)
		}
	})
}
```

- [ ] **Step 3: Test it works**

Run: `SYCK_SCAN_SEVERITY=HIGH /tmp/syck scan . 2>&1 | head -5`

Expected: filter applied at HIGH severity (no LOW findings).

- [ ] **Step 4: Commit**

```bash
git add cmd/env.go cmd/scan.go
git commit -m "feat: support SYCK_SCAN_* env vars for all flags"
```

---

### Task 2: `--progress` TUI progress bar

**Files:**
- Modify: `cmd/scan.go` — add `--progress` flag
- Modify: `internal/scanner/scanner.go` — add `Progress` callback to Config
- Modify: `internal/scanner/scan.go` — call progress callback
- Add: `go.mod` — add `github.com/schollz/progressbar/v3` dep
- Add: `internal/progress/progress.go` — TUI progress wrapper

- [ ] **Step 1: Add progressbar dep**

Run: `go get github.com/schollz/progressbar/v3@latest`

- [ ] **Step 2: Create progress wrapper**

```go
package progress

import (
	"io"
	"sync/atomic"

	"github.com/schollz/progressbar/v3"
)

type Bar struct {
	pb     *progressbar.ProgressBar
	cur    atomic.Int64
	findings atomic.Int64
}

func New(total int, w io.Writer) *Bar {
	return &Bar{
		pb: progressbar.NewOptions(total,
			progressbar.OptionSetWriter(w),
			progressbar.OptionSetDescription("scanning"),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetPredictTime(true),
		),
	}
}

func (b *Bar) Add(n int) { _ = b.pb.Add(n) }

func (b *Bar) AddFinding(n int) { b.findings.Add(int64(n)) }

func (b *Bar) Finish() { _ = b.pb.Finish() }
```

- [ ] **Step 3: Add Progress func field to Config**

```go
type Config struct {
	// ... existing fields ...
	Progress func(filesScanned, findings int)  // called per file; nil = no-op
}
```

- [ ] **Step 4: Wire progress callback in scanContent**

In `internal/scanner/scan.go` `scanContent` or `ScanPaths`, after each file is scanned, call `cfg.Progress(filesScanned, findingsCount)` if non-nil.

- [ ] **Step 5: Add --progress CLI flag**

In `cmd/scan.go` `init()`:
```go
scanCmd.Flags().BoolVar(&progressFlag, "progress", false, "show TUI progress bar on stderr")
```

In `runScan()`:
```go
if progressFlag && !quiet && !pipe {
	bar := progress.New(fileCount, os.Stderr)
	defer bar.Finish()
	scanCfg.Progress = bar.Add
}
```

- [ ] **Step 6: Test**

Run: `/tmp/syck scan . --progress 2>&1 | tail -5`

Expected: progress bar shown on stderr, final count at end.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum cmd/scan.go internal/progress/ internal/scanner/
git commit -m "feat: add --progress TUI progress bar"
```

---

### Task 3: SARIF upload

**Files:**
- Add: `cmd/upload_sarif.go` — subcommand
- Add: `docs/examples/github-actions.yml` — example workflow

- [ ] **Step 1: Create cmd/upload_sarif.go**

```go
package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var uploadSarifCmd = &cobra.Command{
	Use:   "upload-sarif",
	Short: "Upload a SARIF file to GitHub Code Scanning",
	RunE: func(cmd *cobra.Command, args []string) error {
		sarifPath, _ := cmd.Flags().GetString("file")
		repo, _ := cmd.Flags().GetString("repo")
		commit, _ := cmd.Flags().GetString("commit")
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return fmt.Errorf("GITHUB_TOKEN env var required")
		}
		data, err := os.ReadFile(sarifPath)
		if err != nil {
			return err
		}
		url := fmt.Sprintf("https://api.github.com/repos/%s/code-scanning/sarifs", repo)
		body := fmt.Sprintf(`{"commit_sha":"%s","sarif":%s}`, commit, string(data))
		req, _ := http.NewRequest("POST", url, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("upload failed: HTTP %d", resp.StatusCode)
		}
		fmt.Println("SARIF uploaded successfully")
		return nil
	},
}

func init() {
	uploadSarifCmd.Flags().String("file", "", "path to SARIF file (required)")
	uploadSarifCmd.Flags().String("repo", "", "OWNER/REPO (required)")
	uploadSarifCmd.Flags().String("commit", "", "commit SHA (required)")
	rootCmd.AddCommand(uploadSarifCmd)
}
```

- [ ] **Step 2: Add example workflow**

Create `docs/examples/github-actions.yml`:
```yaml
name: Secrets Scan
on: [push, pull_request]
jobs:
  syck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install syck
        run: go install github.com/RA000WL/syck@latest
      - name: Scan
        run: syck scan . --format sarif -o results.sarif --no-color || true
      - name: Upload SARIF
        if: always()
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          syck upload-sarif \
            --file results.sarif \
            --repo ${{ github.repository }} \
            --commit ${{ github.sha }}
```

- [ ] **Step 3: Test**

Run: `go build -o /tmp/syck . && /tmp/syck upload-sarif --help`

Expected: shows help for upload-sarif.

- [ ] **Step 4: Commit**

```bash
git add cmd/upload_sarif.go docs/examples/github-actions.yml
git commit -m "feat: add upload-sarif subcommand + GitHub Actions example"
```

---

### Task 4: Update docs

- [ ] **Step 1: Add V1.7 row to ROADMAP status table**

```markdown
| V1.7  | Operational polish: env config, TUI progress, SARIF upload | Complete |
```

- [ ] **Step 2: Add V1.7 phase section to ROADMAP.md**

Add a `### V1.7 — Operational Polish` section before `## V1 Acceptance Criteria`.

- [ ] **Step 3: Mark V1.7 items complete in CHECKLIST.md**

Update:
- [x] --progress (TUI progress bar) — V1.7
- [x] SYCK_* env var config — V1.7
- [x] GitHub Code Scanning upload — V1.7

- [ ] **Step 4: Commit**

```bash
git add ROADMAP.md CHECKLIST.md
git commit -m "docs: mark V1.7 complete in ROADMAP and CHECKLIST"
```
