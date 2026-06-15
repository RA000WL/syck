package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestFilterNewOnly(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: true},
		{RuleName: "b", IsNew: false},
		{RuleName: "c", IsNew: true},
	}
	result := FilterNewOnly(findings)
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
	if result[0].RuleName != "a" || result[1].RuleName != "c" {
		t.Errorf("unexpected results: %v", result)
	}
}

func TestFilterNewOnly_AllNew(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: true},
	}
	result := FilterNewOnly(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
}

func TestFilterNewOnly_NoneNew(t *testing.T) {
	findings := []finding.Finding{
		{RuleName: "a", IsNew: false},
	}
	result := FilterNewOnly(findings)
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}
