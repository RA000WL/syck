package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestCorrelatorEmpty(t *testing.T) {
	c := NewCorrelator()
	got := c.Correlate(nil)
	if len(got) != 0 {
		t.Errorf("Correlate(nil) returned %d, want 0", len(got))
	}
}

func TestCorrelatorWithDetector(t *testing.T) {
	c := NewCorrelator()
	c.RegisterDetector(stubDetector{})
	got := c.Correlate([]finding.Finding{{RuleName: "x", File: "a", Line: 1}})
	if len(got) != 1 {
		t.Errorf("Correlate returned %d, want 1", len(got))
	}
}

func TestCorrelatorRegisterNilDetector(t *testing.T) {
	c := NewCorrelator()
	c.RegisterDetector(nil)
	got := c.Correlate([]finding.Finding{{RuleName: "x", File: "a", Line: 1}})
	if len(got) != 0 {
		t.Errorf("Correlate returned %d after nil register, want 0", len(got))
	}
}

type stubDetector struct{}

func (stubDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	return []CorrelatedFinding{{Type: "stub"}}
}
