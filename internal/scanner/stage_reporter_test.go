package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestReporterStageNoOps(t *testing.T) {
	s := NewReporterStage(false, false)
	in := []finding.Finding{{RuleName: "a"}, {RuleName: "a"}}
	got := s.Process(in)
	if len(got) != 2 {
		t.Errorf("want 2 findings (no dedup, no downgrade), got %d", len(got))
	}
}
