package rules

import "testing"

func TestRuleExtendedFields(t *testing.T) {
	yaml := `
rules:
  - name: github_pat
    severity: CRITICAL
    pattern: 'github_pat_[A-Za-z0-9_]{80,255}'
    entropy_threshold: 4.5
    context_keywords: [github]
    requires_context: true
    verify: true
    version: "1"
`
	rs, err := loadFromString(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := rs.Rules[0]
	if r.EntropyThreshold != 4.5 {
		t.Errorf("EntropyThreshold = %v, want 4.5", r.EntropyThreshold)
	}
	if len(r.ContextKeywords) != 1 || r.ContextKeywords[0] != "github" {
		t.Errorf("ContextKeywords = %v, want [github]", r.ContextKeywords)
	}
	if !r.RequiresContext {
		t.Error("RequiresContext = false, want true")
	}
	if !r.Verify {
		t.Error("Verify = false, want true")
	}
	if r.Version != "1" {
		t.Errorf("Version = %q, want %q", r.Version, "1")
	}
}
