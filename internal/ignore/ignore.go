package ignore

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

func Fingerprint(f finding.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.RuleName + ":" + f.Secret + ":" + f.File))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func LoadIgnoreFile(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ignore := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			ignore[line] = true
		}
	}
	return ignore, nil
}

func Filter(findings []finding.Finding, ignoreSet map[string]bool) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		fp := Fingerprint(f)
		if !ignoreSet[fp] {
			result = append(result, f)
		}
	}
	return result
}
