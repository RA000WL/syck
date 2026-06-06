package ignore

import (
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

func Fingerprint(f finding.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.RuleName + ":" + f.Secret + ":" + f.File))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// IgnoreSet is a parsed `.syckignore` file: a set of sha256 fingerprints
// plus a list of compiled regex patterns. A finding is suppressed if its
// fingerprint is in the set OR if any pattern matches its secret/file.
type IgnoreSet struct {
	Fingerprints map[string]bool
	Patterns     []*regexp.Regexp
}

func LoadIgnoreFile(path string) (*IgnoreSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	set := &IgnoreSet{
		Fingerprints: make(map[string]bool),
	}
	for _, line := range strings.Split(string(data), "\n") {
		// strip trailing comment
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// pattern: prefixed with "re:" — compiled and stored
		if strings.HasPrefix(line, "re:") {
			pat, err := regexp.Compile(strings.TrimPrefix(line, "re:"))
			if err != nil {
				return nil, fmt.Errorf("invalid ignore pattern %q: %w", line, err)
			}
			set.Patterns = append(set.Patterns, pat)
			continue
		}
		// fingerprint: bare hex sha256
		set.Fingerprints[line] = true
	}
	return set, nil
}

func Filter(findings []finding.Finding, set *IgnoreSet) []finding.Finding {
	if set == nil {
		return findings
	}
	result := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if set.Fingerprints[Fingerprint(f)] {
			continue
		}
		if matchAny(set.Patterns, f.Secret) || matchAny(set.Patterns, f.File) {
			continue
		}
		result = append(result, f)
	}
	return result
}

func matchAny(patterns []*regexp.Regexp, s string) bool {
	for _, p := range patterns {
		if p.MatchString(s) {
			return true
		}
	}
	return false
}
