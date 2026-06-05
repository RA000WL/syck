package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestRuleStage(t *testing.T) {
	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs := loadTestRuleSet(t, yaml)
	s := NewRuleStage(rs, finding.ParseSeverity("LOW"))
	got := s.Process("hello TOKEN_ABCDEF12 world", "x.txt", 1)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].RuleName != "token" {
		t.Errorf("RuleName = %q, want token", got[0].RuleName)
	}
}

func loadTestRuleSet(t *testing.T, yaml string) *rules.RuleSet {
	t.Helper()
	rs, err := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}
