package scanner

import (
	"github.com/RA000WL/syck/internal/finding"
)

type ReporterStage struct {
	Dedup     bool
	Downgrade bool
}

func NewReporterStage(dedup, downgrade bool) *ReporterStage {
	return &ReporterStage{Dedup: dedup, Downgrade: downgrade}
}

func (s *ReporterStage) Process(in []finding.Finding) []finding.Finding {
	out := in
	if s.Downgrade {
		out = DowngradeFP(out)
	}
	if s.Dedup {
		out = finding.Deduplicate(out)
	}
	return out
}
