package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestVerifierStagePassthrough(t *testing.T) {
	s := NewVerifierStage()
	in := []finding.Finding{{RuleName: "unknown_rule_xyzzy", Secret: "value"}}
	got := s.Process(in)
	if got[0].VerificationStatus != "" {
		t.Errorf("VerificationStatus = %q, want empty (unknown rule, no validation)", got[0].VerificationStatus)
	}
}
