package ruletest

import "testing"

func TestGeneratePositiveFound(t *testing.T) {
	lines := GeneratePositive("test_rule")
	if len(lines) == 0 {
		t.Fatal("expected test_rule positive data to exist")
	}
}

func TestGeneratePositiveMissing(t *testing.T) {
	lines := GeneratePositive("nonexistent_rule_xyz")
	if lines != nil {
		t.Errorf("expected nil for missing rule, got %d lines", len(lines))
	}
}

func TestGenerateNegative(t *testing.T) {
	lines := GenerateNegative()
	if len(lines) == 0 {
		t.Fatal("expected negative corpus to have data")
	}
	if len(lines) < 900 {
		t.Errorf("expected ~1000 negative lines, got %d", len(lines))
	}
}

func TestGenerateAllRules(t *testing.T) {
	for name := range positiveGenerators {
		lines := GeneratePositive(name)
		if len(lines) != 8 {
			t.Errorf("rule %q: expected 8 positive lines, got %d", name, len(lines))
		}
	}
}
