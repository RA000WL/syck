package gitscan

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/fileutil"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/scanner"
)

var textExts = fileutil.TextExtensions

// gitStderr renders the git process's own stderr as a suffix for an error
// message, or "" when git wrote nothing to stderr or the failure was not an
// exec exit. exec.Cmd.Output leaves ExitError.Stderr populated with a prefix of
// the child's stderr precisely because it leaves c.Stderr nil, which is where
// the diagnostic text ("fatal: not a git repository ...") lands.
func gitStderr(err error) string {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return ""
	}
	msg := strings.TrimSpace(string(ee.Stderr))
	if msg == "" {
		return ""
	}
	return ": " + msg
}

func ScanHistory(repoPath string, cfg scanner.Config) ([]finding.Finding, error) {
	var allFindings []finding.Finding
	seen := make(map[string]bool)

	logCmd := exec.Command("git", "-C", repoPath, "log", "--all", "--format=%H", "--diff-filter=AM")
	logOut, err := logCmd.Output()
	if err != nil {
		// A failure here means the history could not be enumerated at all —
		// almost always because repoPath is not a git repository. Returning
		// (nil, nil) made `syck scan --git-history /not/a/repo` report exactly
		// what a clean scan reports, so the user could not tell "no secrets"
		// from "nothing was scanned". Name the path so that, when several
		// repos are scanned, the failing one is identifiable, and carry the
		// underlying git error so the cause is diagnosable without re-running
		// git by hand.
		//
		// cmd/scan_run.go still downgrades this to a warning and exits 0;
		// making it fatal is deliberately left as a separate decision.
		return nil, fmt.Errorf("gitscan: git log failed in %q: %w%s", repoPath, err, gitStderr(err))
	}
	commits := strings.Fields(string(logOut))

	for _, commit := range commits {
		diffCmd := exec.Command("git", "-C", repoPath, "diff-tree", "--root", "--no-commit-id", "-r", "--name-only", commit)
		diffOut, err := diffCmd.Output()
		if err != nil {
			continue
		}
		files := strings.Fields(string(diffOut))
		if len(files) == 0 {
			continue
		}

		for _, fp := range files {
			ext := strings.ToLower(filepath.Ext(fp))
			if !textExts[ext] {
				continue
			}

			showCmd := exec.Command("git", "-C", repoPath, "show", commit+":"+fp)
			content, err := showCmd.Output()
			if err != nil {
				continue
			}

			if len(content) == 0 {
				continue
			}

			gitPath := "git:" + commit[:8] + ":" + fp
			findings := scanner.ScanContent(string(content), gitPath, cfg)

			for _, f := range findings {
				key := f.RuleName + ":" + f.Secret
				if seen[key] {
					continue
				}
				seen[key] = true
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings, nil
}
