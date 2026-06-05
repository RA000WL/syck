package scanner

import (
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
)

type EntropyStage struct{}

func NewEntropyStage() *EntropyStage { return &EntropyStage{} }

func (s *EntropyStage) Process(line, path string, lineno int) []finding.Finding {
	if !entropy.HasSecretContext(line) {
		return nil
	}
	var out []finding.Finding
	for _, m := range entropy.EntropyTokenRe.FindAllStringIndex(line, -1) {
		token := line[m[0]:m[1]]
		if !entropy.IsEntropyTokenMatch(token) {
			continue
		}
		out = append(out, finding.Finding{
			File:     path,
			Line:     lineno,
			RuleName: "entropy_token",
			Severity: finding.ParseSeverity("LOW"),
			Secret:   token,
			Context:  finding.Truncate(line),
			Entropy:  entropy.Shannon(token),
		})
	}
	return out
}
