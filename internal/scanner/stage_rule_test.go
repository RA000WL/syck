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

func TestRuleStageFindingShape(t *testing.T) {
	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs := loadTestRuleSet(t, yaml)
	s := NewRuleStage(rs, finding.ParseSeverity("LOW"))
	got := s.Process("hello TOKEN_ABCDEF12 world", "x.txt", 1)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.File != "x.txt" {
		t.Errorf("File = %q, want x.txt", f.File)
	}
	if f.Line != 1 {
		t.Errorf("Line = %d, want 1", f.Line)
	}
	if f.RuleName != "token" {
		t.Errorf("RuleName = %q, want token", f.RuleName)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %v, want SeverityHigh", f.Severity)
	}
	if f.Secret != "TOKEN_ABCDEF12" {
		t.Errorf("Secret = %q, want TOKEN_ABCDEF12", f.Secret)
	}
	if f.Context != "hello TOKEN_ABCDEF12 world" {
		t.Errorf("Context = %q, want full line", f.Context)
	}
	if f.Column != 0 {
		t.Errorf("Column = %d, want 0 (V1 line-based, no column tracking)", f.Column)
	}
	if f.Entropy != 0 {
		t.Errorf("Entropy = %v, want 0 (V1 RuleStage doesn't compute entropy)", f.Entropy)
	}
	if f.ConfidenceBand != "" {
		t.Errorf("ConfidenceBand = %q, want empty (ConfidenceBand set in M9 stage, not here)", f.ConfidenceBand)
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
