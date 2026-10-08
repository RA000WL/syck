package gitscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	// Single commit: with --root, diff-tree enumerates the initial commit's
	// files against the empty tree, so no parent commit is needed to route
	// the secret into the history scan.
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

// TestScanHistoryScansInitialCommit covers the blind spot where a secret is
// committed in the first commit and deleted in a later one: it is absent from
// the working tree (so the ordinary scan misses it) and, without --root,
// `git diff-tree` never lists it either — so nothing scans it at all.
func TestScanHistoryScansInitialCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	gitEnv(t)

	dir := t.TempDir()
	git(t, dir, "init")

	// Commit 1: the secret is present.
	content := "aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "config.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "add config")

	// Commit 2: the secret is gone from the working tree.
	git(t, dir, "rm", "config.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "remove config")

	if _, err := os.Stat(filepath.Join(dir, "config.txt")); !os.IsNotExist(err) {
		t.Fatalf("precondition: config.txt should be absent from the working tree (stat err = %v)", err)
	}

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
		t.Fatalf("expected >= 1 finding for a secret present only in the initial commit, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Secret, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected the AWS example key, got %+v", findings[0])
	}
}

// TestScanHistoryNoDoubleReportForRootAndLaterCommit pins the de-dup
// behaviour that --root relies on: the same secret now appears in both the
// initial commit (via --root) and the later commit that touches the file, and
// must be reported exactly once.
func TestScanHistoryNoDoubleReportForRootAndLaterCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	gitEnv(t)

	dir := t.TempDir()
	git(t, dir, "init")

	// Commit 1: the secret is introduced.
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte("aws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "config.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "add config")

	// Commit 2: unrelated churn, so the initial commit is not the last one.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "README.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "readme")

	// Commit 3: the same secret in a modified version of the same file.
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte("# rotated nothing, just a comment\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "config.txt")
	git(t, dir, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "touch config")

	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	cfg := scanner.Config{Rules: rs, MinSeverity: finding.SeverityLow}

	findings, err := ScanHistory(dir, cfg)
	if err != nil {
		t.Fatalf("ScanHistory: %v", err)
	}

	var keyFindings []finding.Finding
	for _, f := range findings {
		if strings.Contains(f.Secret, "AKIAIOSFODNN7EXAMPLE") {
			keyFindings = append(keyFindings, f)
		}
	}
	if len(keyFindings) != 1 {
		t.Errorf("expected exactly 1 finding for AKIAIOSFODNN7EXAMPLE (present in the root commit and commit 3), got %d: %+v", len(keyFindings), keyFindings)
	}
}

// TestScanHistoryNonRepoErrors pins the descriptive error for a path that was
// never `git init`'d. ScanHistory previously swallowed the `git log` failure and
// returned (nil, nil), so `syck scan --git-history /not/a/repo` was
// indistinguishable from a clean scan. The caller still downgrades this to a
// warning (see cmd/scan_run.go), which is why the error text is the only thing
// telling the user that no history was scanned — hence the two message
// assertions, not just a nil check.
func TestScanHistoryNonRepoErrors(t *testing.T) {
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
	if err == nil {
		t.Fatalf("ScanHistory(%q) returned err == nil on a path that is not a git repo: "+
			"findings=%d. A caller that asked for --git-history and got nothing back "+
			"cannot tell that apart from a clean scan, so the git failure must be reported.",
			dir, len(findings))
	}
	// The message must name the path, or the user has no way to tell WHICH
	// repo failed when scanning several.
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("error %q does not name the offending path %q", err.Error(), dir)
	}
	// The message must also carry the underlying git failure, so the cause is
	// diagnosable without re-running git by hand.
	if !strings.Contains(err.Error(), "git") {
		t.Errorf("error %q does not mention the underlying git failure", err.Error())
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings alongside the error, got %d", len(findings))
	}
}
