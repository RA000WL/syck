package gitscan

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/scanner"
)

var textExts = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true,
	".cfg": true, ".conf": true, ".env": true, ".sh": true, ".bash": true,
	".zsh": true, ".fish": true, ".bat": true, ".ps1": true, ".rb": true,
	".rs": true, ".java": true, ".kt": true, ".swift": true, ".c": true,
	".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".php": true,
	".pl": true, ".pm": true, ".lua": true, ".r": true, ".scala": true,
	".clj": true, ".hs": true, ".erl": true, ".ex": true, ".exs": true,
	".md": true, ".rst": true, ".html": true, ".htm": true, ".xml": true,
	".svg": true, ".css": true, ".scss": true, ".less": true, ".sql": true,
	".graphql": true, ".gql": true, ".txt": true, ".dockerfile": true,
	".makefile": true, ".gradle": true, ".tf": true, ".tfvars": true,
	".hcl": true, ".properties": true, ".lock": true, ".log": true,
	".csv": true, ".tsv": true, ".pem": true, ".key": true, ".cert": true,
	".crt": true, ".pgp": true, ".gpg": true, ".asc": true,
}

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
