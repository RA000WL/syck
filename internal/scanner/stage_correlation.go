package scanner

import (
	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
)

// CorrelationStage appends the credential pairs internal/correlation finds.
//
// The stage is the decomposition of what correlateFindings does on the active
// scan path, and it shares that function's conversion so the two cannot drift.
// NewPipeline hands it a correlator with no detectors registered, so the
// Pipeline built by NewPipeline never emits a pair; a caller that registers
// detectors gets the same conversion and the same MinSeverity filter.
type CorrelationStage struct {
	cor *correlation.Correlator
	// minSeverity drops correlated findings below it. A stage receives its
	// findings already collected, so it has to apply the floor itself: the rule
	// paths gate on MinSeverity while they match (helpers.go:547 and the
	// sub-scanner calls), and nothing downstream of collection re-checks it.
	minSeverity finding.Severity
}

func NewCorrelationStage(c *correlation.Correlator, minSeverity finding.Severity) *CorrelationStage {
	return &CorrelationStage{cor: c, minSeverity: minSeverity}
}

func (s *CorrelationStage) Process(in []finding.Finding) []finding.Finding {
	if s == nil || s.cor == nil {
		return in
	}
	var pairs []finding.Finding
	for _, cf := range s.cor.Correlate(in) {
		f := correlatedFinding(cf)
		if f.Severity < s.minSeverity {
			continue
		}
		pairs = append(pairs, f)
	}
	return append(in, pairs...)
}
