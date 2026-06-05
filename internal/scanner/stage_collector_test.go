package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestCollectorStagePassthrough(t *testing.T) {
	rs, _ := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, "rules:\n  - name: test\n    severity: HIGH\n    pattern: 'SECRET'\n"))
	s := NewCollectorStage(Config{Rules: rs, MinSeverity: finding.ParseSeverity("LOW")})
	got := s.Process("hello world", "plain.txt")
	if len(got) != 0 {
		t.Errorf("plain text produced %d findings, want 0", len(got))
	}
}

func TestCollectorStageExtractsEndpoints(t *testing.T) {
	rs, _ := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, "rules:\n  - name: test\n    severity: HIGH\n    pattern: 'SECRET'\n"))
	s := NewCollectorStage(Config{Rules: rs, MinSeverity: finding.ParseSeverity("LOW")})
	got := s.Process(`fetch("https://api.example.com/admin")`, "app.js")
	if len(got) == 0 {
		t.Fatal("expected at least one finding from JS file")
	}
}
