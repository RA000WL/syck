package json_scanner

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

var secretKeyRE = regexp.MustCompile(`(?i)^(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|access[_-]?token|auth[_-]?token|auth[_-]?key|client[_-]?secret|client[_-]?id|private[_-]?key|ssh[_-]?key|encryption[_-]?key|signing[_-]?key|bearer|credential|refresh[_-]?token|session[_-]?key|secret[_-]?key|master[_-]?key)$`)

const maxJSONScanSize = 10 * 1024 * 1024

func ScanJSONFile(path string, content string, rs *rules.RuleSet, minSev finding.Severity) []finding.Finding {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".json" {
		return nil
	}
	if len(content) > maxJSONScanSize {
		return nil
	}

	var data interface{}
	if err := json.Unmarshal([]byte(content), &data); err != nil {
		return nil
	}

	var findings []finding.Finding
	scanValue(data, "", path, rs, minSev, &findings)
	return findings
}

func scanValue(value interface{}, keyPath string, path string, rs *rules.RuleSet, minSev finding.Severity, findings *[]finding.Finding) {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, child := range v {
			kp := keyPath
			if kp == "" {
				kp = k
			} else {
				kp = kp + "." + k
			}
			scanValue(child, kp, path, rs, minSev, findings)
		}

	case []interface{}:
		for i, child := range v {
			kp := keyPath
			if kp == "" {
				kp = "[" + itoa(i) + "]"
			} else {
				kp = kp + "[" + itoa(i) + "]"
			}
			scanValue(child, kp, path, rs, minSev, findings)
		}

	case string:
		if v == "" {
			return
		}
		keyName := lastKey(keyPath)
		ctx := "json key: " + keyPath

		// Check if key matches known secret-key names
		if secretKeyRE.MatchString(keyName) {
			e := entropy.Shannon(v)
			if len(v) >= 8 && !isAllDigits(v) && e >= 3.0 {
				*findings = append(*findings, finding.Finding{
					File:     path,
					Line:     0,
					Column:   0,
					RuleName: "json_" + keyName,
					Severity: finding.SeverityMedium,
					Secret:   truncate(v, 500),
					Context:  ctx,
					Entropy:  e,
				})
			}
		}

		// Run all rules against the value
		for _, rule := range rs.Rules {
			sev := finding.ParseSeverity(rule.Severity)
			if sev < minSev {
				continue
			}
			if rule.Compiled() == nil {
				continue
			}
			matches := rule.MatchAll(v)
			for _, m := range matches {
				var secret string
				if m[1] <= len(v) {
					secret = v[m[0]:m[1]]
				} else {
					secret = v[m[0]:]
				}
				e := entropy.Shannon(secret)
				if e < 2.0 {
					continue
				}
				*findings = append(*findings, finding.Finding{
					File:     path,
					Line:     0,
					Column:   0,
					RuleName: "json_" + rule.Name,
					Severity: sev,
					Secret:   secret,
					Context:  ctx,
					Entropy:  e,
				})
			}
		}
	}
}

func lastKey(keyPath string) string {
	// Handle formats like "foo.bar.baz" or "arr[0].key" or "[0]"
	if idx := strings.LastIndex(keyPath, "."); idx >= 0 {
		return keyPath[idx+1:]
	}
	if idx := strings.LastIndex(keyPath, "["); idx >= 0 {
		return keyPath[idx:]
	}
	return keyPath
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
