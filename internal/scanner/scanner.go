package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/jsrecon"
	"github.com/RA000WL/syck/internal/rules"
)

type Config struct {
	Workers     int
	MaxFileSize int64
	Exclude     *regexp.Regexp
	Rules       *rules.RuleSet
	MinSeverity finding.Severity
	NoDedup     bool
	Debug       bool
}

var textExtensions = map[string]bool{
	".txt": true, ".go": true, ".py": true, ".js": true, ".ts": true,
	".jsx": true, ".tsx": true, ".json": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".bat": true,
	".ps1": true, ".rb": true, ".rs": true, ".java": true, ".kt": true,
	".swift": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true,
	".cs": true, ".php": true, ".pl": true, ".pm": true, ".lua": true,
	".r": true, ".scala": true, ".clj": true, ".hs": true, ".erl": true,
	".ex": true, ".exs": true, ".md": true, ".rst": true, ".html": true,
	".htm": true, ".xml": true, ".svg": true, ".css": true, ".scss": true,
	".less": true, ".sql": true, ".graphql": true, ".gql": true,
	".dockerfile": true, ".makefile": true, ".gradle": true,
	".tf": true, ".tfvars": true, ".hcl": true, ".properties": true,
	".lock": true, ".log": true, ".csv": true, ".tsv": true,
	".pem": true, ".key": true, ".cert": true, ".crt": true,
	".pgp": true, ".gpg": true, ".asc": true,
}

var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "__pycache__": true,
	"node_modules": true, ".venv": true, "venv": true, "env": true,
	".tox": true, ".eggs": true, "eggs": true, ".mypy_cache": true,
	".pytest_cache": true, ".cache": true, "target": true, "build": true,
	"dist": true, ".next": true, ".nuxt": true, ".output": true,
	"vendor": true, ".bundle": true, ".gradle": true, "bin": true,
	"obj": true, ".terraform": true, ".serverless": true,
}

func ScanPaths(paths []string, cfg Config) ([]finding.Finding, error) {
	var (
		allFindings []finding.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
		sem         = make(chan struct{}, cfg.Workers)
	)

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			sem <- struct{}{}
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(path, cfg)
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					mu.Unlock()
				}
			}(root)
			continue
		}

		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if cfg.Exclude != nil && cfg.Exclude.MatchString(path) {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !textExtensions[ext] && !isTextFile(path) {
				return nil
			}
			if info.Size() > cfg.MaxFileSize {
				return nil
			}

			sem <- struct{}{}
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(fp, cfg)
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					mu.Unlock()
				}
			}(path)
			return nil
		})
		if err != nil {
			continue
		}
	}

	wg.Wait()

	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
	}

	return allFindings, nil
}

func ScanFile(path string, cfg Config) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var content strings.Builder
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))
	lineNum := 0
	var findings []finding.Finding

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++
		content.WriteString(line)
		content.WriteByte('\n')

		for _, rule := range cfg.Rules.Rules {
			matches := rule.MatchAll(line)
			for _, m := range matches {
				var secret string
				if m[1] <= len(line) {
					secret = line[m[0]:m[1]]
				} else {
					secret = line[m[0]:]
				}

				sev := finding.ParseSeverity(rule.Severity)
				if sev < cfg.MinSeverity {
					continue
				}

				e := entropy.Shannon(secret)
				if e < 2.0 {
					continue
				}

				findings = append(findings, finding.Finding{
					File:     path,
					Line:     lineNum,
					Column:   m[0],
					RuleName: rule.Name,
					Severity: sev,
					Secret:   secret,
					Context:  strings.TrimSpace(line),
					Entropy:  e,
				})
			}
		}

		decodedFindings := decoder.DecodeAndRescan(line, path, lineNum, cfg.Rules, cfg.MinSeverity)
		findings = append(findings, decodedFindings...)
	}

	fullContent := content.String()
	jsFindings := jsrecon.ReconstructAndScan(fullContent, path, cfg.Rules, cfg.MinSeverity)
	findings = append(findings, jsFindings...)

	return findings, nil
}

func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, 512)
	n, err := reader.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	buf = buf[:n]

	for _, b := range buf {
		if b == 0 {
			return false
		}
	}
	return true
}
