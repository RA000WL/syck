package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
)

func TestCorrelationStagePassthrough(t *testing.T) {
	s := NewCorrelationStage(correlation.NewCorrelator())
	findings := []finding.Finding{{RuleName: "x", File: "a", Line: 1}}
	got := s.Process(findings)
	if len(got) != 1 {
		t.Errorf("Process returned %d, want 1 (unchanged)", len(got))
	}
}
