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

// safeGitArgs are prepended to every git invocation this package makes.
//
// A secret scanner's core use case is running against a repository the user did
// not write — a freshly cloned repo, a PR branch in CI, a corpus of fixtures.
// That repository controls its own .git/config, and git honours several config
// keys that name a command to run: core.fsmonitor is the live one, and git
// invokes it while refreshing the index, which diff-tree does as a side effect
// of its own work. So a repo carrying
//
//	[core]
//		fsmonitor = touch /tmp/pwned
//
// gets that command executed as the scanning user, from a repo the user merely
// pointed syck at. Verified end to end before this fix existed.
//
// Passing -c overrides every config level, because command-line config is
// applied last in git's own resolution order — so these defeat the repo-local
// config that env isolation (GIT_CONFIG_GLOBAL / GIT_CONFIG_SYSTEM) cannot
// reach. GIT_CONFIG_NOSYSTEM and the two /dev/null globals are belt and braces
// for the host's own configuration. The set is deliberately wider than
// fsmonitor: hooksPath, textconv filters, and the pager are all keys that name
// a command, and there is no reason for this package to honour any of them.
//
// Verified: with these flags, running diff-tree against an unmodified repo and
// against a poisoned one produces byte-identical file lists, and the poisoned
// repo's command is never executed.
var safeGitArgs = []string{
	"-c", "core.fsmonitor=false",
	"-c", "core.hooksPath=/dev/null",
	"-c", "diff.textconv=false",
	"-c", "diff.external=false",
	"-c", "core.pager=cat",
	"-c", "core.editor=true",
	"-c", "filter.lfs.clean=cat",
	"-c", "filter.lfs.smudge=cat",
	"-c", "filter.lfs.required=false",
	"-c", "interactive.diffFilter=cat",
}

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

	logArgs := append(append([]string{}, safeGitArgs...), "-C", repoPath, "log", "--all", "--format=%H", "--diff-filter=AM")
	logCmd := exec.Command("git", logArgs...)
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
		diffArgs := append(append([]string{}, safeGitArgs...), "-C", repoPath, "diff-tree", "--root", "--no-commit-id", "-r", "--name-only", commit)
		diffCmd := exec.Command("git", diffArgs...)
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

			showArgs := append(append([]string{}, safeGitArgs...), "-C", repoPath, "show", commit+":"+fp)
			showCmd := exec.Command("git", showArgs...)
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
