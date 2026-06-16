package gitscan

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/fileutil"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/scanner"
)

var textExts = fileutil.TextExtensions

func ScanHistory(repoPath string, cfg scanner.Config) ([]finding.Finding, error) {
	var allFindings []finding.Finding
	seen := make(map[string]bool)

	logCmd := exec.Command("git", "-C", repoPath, "log", "--all", "--format=%H", "--diff-filter=AM")
	logOut, err := logCmd.Output()
	if err != nil {
		return nil, nil
	}
	commits := strings.Fields(string(logOut))

	for _, commit := range commits {
		diffCmd := exec.Command("git", "-C", repoPath, "diff-tree", "--no-commit-id", "-r", "--name-only", commit)
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
				if len(key) > 80 {
					key = key[:80]
				}
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
