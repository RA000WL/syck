package scanner

import (
	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
)

type CorrelationStage struct {
	cor *correlation.Correlator
}

func NewCorrelationStage(c *correlation.Correlator) *CorrelationStage {
	return &CorrelationStage{cor: c}
}

func (s *CorrelationStage) Process(in []finding.Finding) []finding.Finding {
	if s == nil || s.cor == nil {
		return in
	}
	correlated := s.cor.Correlate(in)
	for _, c := range correlated {
		in = append(in, finding.Finding{
			File:           c.File,
			Line:           c.Line,
			RuleName:       c.Type,
			ConfidenceBand: c.Confidence,
			Secret:         c.Description,
			Context:        c.Type,
		})
	}
	return in
}
