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
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(RuleSet{Rules: []Rule{tc.rule}})
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestRuleValidatorCaseInsensitiveDuplicate(t *testing.T) {
	v := NewRuleValidator()
	err := v.Validate(RuleSet{Rules: []Rule{
		{Name: "a", Severity: "HIGH", Pattern: "abc"},
		{Name: "A", Severity: "HIGH", Pattern: "def"},
	}})
	if err == nil {
		t.Fatal("expected duplicate error for case-insensitive name collision, got nil")
	}
}

func TestRuleValidatorEmptyRuleset(t *testing.T) {
	v := NewRuleValidator()
	if err := v.Validate(RuleSet{}); err != nil {
		t.Fatalf("empty RuleSet should be valid, got %v", err)
	}
	if err := v.Validate(RuleSet{Rules: nil}); err != nil {
		t.Fatalf("nil rules should be valid, got %v", err)
	}
}
