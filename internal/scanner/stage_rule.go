package scanner

import (
	"strings"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type RuleStage struct {
	rs  *rules.RuleSet
	min finding.Severity
}

func NewRuleStage(rs *rules.RuleSet, min finding.Severity) *RuleStage {
	return &RuleStage{rs: rs, min: min}
}

func (s *RuleStage) Process(line, path string, lineno int) []finding.Finding {
	var out []finding.Finding
	for _, r := range s.rs.Rules {
		sev := r.SeverityInt
		if sev < s.min || r.Compiled() == nil {
			continue
		}
		if r.RequiresContext && !lineHasContextKeyword(line, r.ContextKeywords) {
			continue
		}
		for _, m := range r.MatchAll(line) {
			secret := line[m[0]:m[1]]
			out = append(out, finding.Finding{
				File:     path,
				Line:     lineno,
				RuleName: r.Name,
				Severity: sev,
				Secret:   secret,
				Context:  finding.Truncate(line),
			})
		}
	}
	return out
}

func lineHasContextKeyword(line string, keywords []string) bool {
	lower := strings.ToLower(line)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
