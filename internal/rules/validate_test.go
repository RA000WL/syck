package rules

import "testing"

func TestRuleValidator(t *testing.T) {
	v := NewRuleValidator()
	cases := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{"ok", Rule{Name: "a", Severity: "HIGH", Pattern: "abc"}, false},
		{"empty name", Rule{Severity: "HIGH", Pattern: "abc"}, true},
		{"bad severity", Rule{Name: "a", Severity: "FOO", Pattern: "abc"}, true},
		{"bad pattern", Rule{Name: "a", Severity: "HIGH", Pattern: "[unterminated"}, true},
		{"duplicate name", Rule{Name: "a", Severity: "HIGH", Pattern: "abc"}, false},
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule, cases[3].rule}}); err == nil {
		t.Error("expected error for bad pattern, got nil")
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule}}); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
	if err := v.Validate(RuleSet{Rules: []Rule{cases[0].rule, cases[4].rule}}); err == nil {
		t.Error("expected error for duplicate name, got nil")
	}
}
