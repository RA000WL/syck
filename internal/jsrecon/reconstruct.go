package jsrecon

import (
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

var (
	joinExprRE  = regexp.MustCompile(`\[([^\]]+)\]\s*\.\s*join\s*\(\s*['"]\s*['"]\s*\)`)
	templateRE  = regexp.MustCompile("`([^`$]*)`")
)

const minReconstructLen = 20

type reconstructResult struct {
	lineNo int
	text   string
}

func ReconstructAndScan(
	content string,
	path string,
	rs *rules.RuleSet,
	minSev finding.Severity,
) []finding.Finding {
	var findings []finding.Finding

	for _, r := range reconstructConcatenations(content) {
		findings = append(findings, scanReconstructed(r.text, r.lineNo, "reconstructed_concat", path, rs, minSev)...)
	}
	for _, r := range reconstructJoins(content) {
		findings = append(findings, scanReconstructed(r.text, r.lineNo, "reconstructed_join", path, rs, minSev)...)
	}
	for _, r := range reconstructTemplates(content) {
		findings = append(findings, scanReconstructed(r.text, r.lineNo, "reconstructed_template", path, rs, minSev)...)
	}

	return findings
}

func reconstructConcatenations(content string) []reconstructResult {
	var results []reconstructResult
	lines := strings.Split(content, "\n")

	for lineno, line := range lines {
		parts := extractConcatChain(line)
		if len(parts) >= 2 {
			reconstructed := strings.Join(parts, "")
			if len(reconstructed) >= minReconstructLen {
				results = append(results, reconstructResult{lineNo: lineno + 1, text: reconstructed})
			}
		}
	}
	return results
}

func extractConcatChain(line string) []string {
	for i := 0; i < len(line); i++ {
		if line[i] == '+' {
			before := line[:i]
			after := line[i+1:]

			leftParts := extractStringLiterals(before)
			rightParts := extractStringLiterals(after)

			if len(leftParts) > 0 && len(rightParts) > 0 {
				lastLeft := leftParts[len(leftParts)-1]
				firstRight := rightParts[0]

				rest := before[:len(before)-len(lastLeft)]
				leftChain := extractConcatChain(strings.TrimSpace(rest))

				var result []string
				result = append(result, leftChain...)
				result = append(result, lastLeft)
				result = append(result, firstRight)

				rightRest := after[len(firstRight):]
				rightRemaining := extractConcatChain(strings.TrimSpace(rightRest))
				result = append(result, rightRemaining...)

				return result
			}
		}
	}

	parts := extractStringLiterals(line)
	if len(parts) > 0 && len(strings.Join(parts, "")) >= minReconstructLen {
		return parts
	}
	return nil
}

func extractStringLiterals(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var parts []string
	i := 0
	for i < len(s) {
		if s[i] == '"' || s[i] == '\'' {
			quote := s[i]
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' && j+1 < len(s) {
					j += 2
					continue
				}
				if s[j] == quote {
					parts = append(parts, s[i+1:j])
					i = j + 1
					break
				}
				j++
			}
			if j >= len(s) {
				i++
			}
		} else {
			i++
		}
	}
	return parts
}

func reconstructJoins(content string) []reconstructResult {
	var results []reconstructResult
	lines := strings.Split(content, "\n")

	for lineno, line := range lines {
		matches := joinExprRE.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			inner := m[1]
			parts := extractStringLiterals(inner)
			if len(parts) >= 2 {
				reconstructed := strings.Join(parts, "")
				if len(reconstructed) >= minReconstructLen {
					results = append(results, reconstructResult{lineNo: lineno + 1, text: reconstructed})
				}
			}
		}
	}
	return results
}

func reconstructTemplates(content string) []reconstructResult {
	var results []reconstructResult
	lines := strings.Split(content, "\n")

	for lineno, line := range lines {
		matches := templateRE.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			static := m[1]
			if len(static) >= minReconstructLen {
				results = append(results, reconstructResult{lineNo: lineno + 1, text: static})
			}
		}
	}
	return results
}

func scanReconstructed(
	reconstructed string,
	lineno int,
	tag string,
	path string,
	rs *rules.RuleSet,
	minSev finding.Severity,
) []finding.Finding {
	var findings []finding.Finding

	if len(reconstructed) > 200 {
		reconstructed = reconstructed[:200]
	}

	context := "js reconstructed: " + reconstructed

	for _, rule := range rs.Rules {
		sev := finding.ParseSeverity(rule.Severity)
		if sev < minSev {
			continue
		}
		if rule.Compiled() == nil {
			continue
		}
		matches := rule.MatchAll(reconstructed)
		for _, m := range matches {
			var secret string
			if m[1] <= len(reconstructed) {
				secret = reconstructed[m[0]:m[1]]
			} else {
				secret = reconstructed[m[0]:]
			}

			e := entropy.Shannon(secret)
			if e < 2.0 {
				continue
			}

			findings = append(findings, finding.Finding{
				File:     path,
				Line:     lineno,
				Column:   0,
				RuleName: tag + "_" + rule.Name,
				Severity: sev,
				Secret:   secret,
				Context:  context,
				Entropy:  e,
			})
		}
	}
	return findings
}
