package json_scanner

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/decoder"
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
			// This 3.0 belongs to the key-name heuristic, not to any rule, so it
			// stays literal. Do not "unify" it with the rule-match gate below:
			// there is no `rule` here to read an entropy_threshold from.
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

		// Context-check text for every rule below: the key path plus the value,
		// which is this path's "line". A JSON value has no line of its own, but
		// the source line a plain file would have offered at this point is
		// `{"<key>": "<value>"}` — BOTH halves. Checking only the value would be
		// narrower than the plain path (whose line carries the key) and checking
		// only the key path would be wider (it would ignore the value's own
		// surroundings). The plain path checks the same text it matches rules
		// against (helpers.go:529), so this keeps the two paths comparable rather
		// than making this one stricter. Computed once here, tested per match
		// where helpers.go:529 tests it.
		ctxText := keyPath + " " + v

		// Run all rules against the value
		for _, rule := range rs.Rules {
			sev := rule.SeverityInt
			if sev < minSev {
				continue
			}
			if rule.Compiled() == nil {
				continue
			}
			matches := rule.MatchAll(v)
			for _, m := range matches {
				if rule.RequiresContext && !hasContextKeyword(ctxText, rule.ContextKeywords) {
					continue
				}
				var secret string
				if m[1] <= len(v) {
					secret = v[m[0]:m[1]]
				} else {
					secret = v[m[0]:]
				}
				e := entropy.Shannon(secret)
				// Rule-match gate: honor the rule's own entropy_threshold when it
				// sets one, else the global 2.0 floor. Deliberately NOT the same
				// gate as the secret-key-NAME heuristic above, which has no rule
				// behind it and keeps its own 3.0.
				if e < decoder.RuleEntropyFloor(rule.EntropyThreshold) {
					continue
				}
				// Same false-positive filters the plain-file path applies after
				// its own floor (helpers.go:555-563), in the same order. All four
				// are suppression-only. Scoped to this ruleset branch: the
				// key-name heuristic above has no matched span and no rule
				// context_keywords, so it is untouched by design.
				if entropy.IsFalsePositiveSecret(secret) {
					continue
				}
				if entropy.IsFalsePositiveToken(secret) {
					continue
				}
				if entropy.IsFalsePositiveEmail(secret) {
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

// hasContextKeyword is a copy of scanner.lineHasContextKeyword (stage_rule.go:44),
// which this package cannot call: internal/scanner imports internal/json_scanner,
// so importing it back would be an import cycle. Same case-insensitive substring
// test over the rule's own context_keywords.
func hasContextKeyword(text string, keywords []string) bool {
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
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
