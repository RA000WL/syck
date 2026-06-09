package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

const maxMultiLineWindow = 10

type MultiLineScanner struct {
	rs  *rules.RuleSet
	min finding.Severity
}

func NewMultiLineScanner(rs *rules.RuleSet, min finding.Severity) *MultiLineScanner {
	return &MultiLineScanner{rs: rs, min: min}
}

func (s *MultiLineScanner) ScanMultiLine(lines []string, path string, startLine int) []finding.Finding {
	if len(lines) < 2 {
		return nil
	}
	content := ""
	for i, l := range lines {
		if i > 0 {
			content += "\n"
		}
		content += l
	}
	var findings []finding.Finding
	for _, rule := range s.rs.Rules {
		if !rule.MultiLine || rule.Compiled() == nil {
			continue
		}
		sev := finding.ParseSeverity(rule.Severity)
		if sev < s.min {
			continue
		}
		matches := rule.MatchAll(content)
		for _, m := range matches {
			end := m[1]
			if end > len(content) {
				end = len(content)
			}
			secret := content[m[0]:end]
			findings = append(findings, finding.Finding{
				File: path, Line: startLine, Column: m[0],
				RuleName: rule.Name + "_multiline", Severity: sev,
				Secret: secret, Context: finding.TruncateContext(content),
			})
		}
	}
	return findings
}
