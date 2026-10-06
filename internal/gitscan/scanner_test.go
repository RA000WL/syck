package gitscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/scanner"
)

// gitEnv isolates git invocations (both the test's own and the ones spawned
// by ScanHistory) from the developer's / CI host's git configuration.
func gitEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	full := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", full...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestScanHistoryFindsCommittedSecret(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	gitEnv(t)

	dir := t.TempDir()
	git(t, dir, "init")

	// First commit establishes a parent so `git diff-tree` (no --root flag in
	// ScanHistory) can enumerate the second commit's files.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "README.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init")

	content := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "config.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "add config")

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	cfg := scanner.Config{Rules: rs, MinSeverity: finding.SeverityLow}

	findings, err := ScanHistory(dir, cfg)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleName == "" || f.File == "" {
		t.Errorf("finding missing RuleName/File: %+v", f)
	}
}

func TestScanHistoryNonRepoIsCleanError(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	gitEnv(t)

	dir := t.TempDir() // never git init'd

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	cfg := scanner.Config{Rules: rs, MinSeverity: finding.SeverityLow}

	findings, err := ScanHistory(dir, cfg)
	// Pinned defect behavior: ScanHistory swallows the git log failure and
	// returns (nil, nil) — no panic, no findings, and no error telling the
	// user the path isn't a repo.
	if err != nil {
		t.Errorf("pinned current behavior is err == nil for non-repo, got %v — if this fires, the defect was fixed; invert this assertion to require an error", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
