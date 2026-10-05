package finding

import (
	"strings"
	"testing"
)

func TestDeduplicateBySecretPreservesLines(t *testing.T) {
	findings := []Finding{
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityLow},
		{RuleName: "r2", Secret: "s3cr3t", File: "a.js", Line: 20, Column: 1, Severity: SeverityLow},
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 30, Column: 1, Severity: SeverityLow},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 findings (one per occurrence), got %d", len(deduped))
	}
	for i, want := range []int{10, 20, 30} {
		if deduped[i].Line != want {
			t.Errorf("deduped[%d].Line = %d, want %d", i, deduped[i].Line, want)
		}
	}
}

func TestDeduplicateBySecretRuleNames(t *testing.T) {
	findings := []Finding{
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityLow},
		{RuleName: "r2", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityHigh},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding (same occurrence), got %d", len(deduped))
	}
	if deduped[0].RuleName != "r2" {
		t.Errorf("RuleName = %q, want %q (highest severity)", deduped[0].RuleName, "r2")
	}
	if len(deduped[0].RuleNames) != 2 || deduped[0].RuleNames[0] != "r2" || deduped[0].RuleNames[1] != "r1" {
		t.Errorf("RuleNames = %q, want [r2 r1] (severity desc)", deduped[0].RuleNames)
	}
	if deduped[0].Severity != SeverityHigh {
		t.Errorf("Severity = %v, want SeverityHigh", deduped[0].Severity)
	}
}

func TestDeduplicateBySecretCrossFileKept(t *testing.T) {
	findings := []Finding{
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityLow},
		{RuleName: "r1", Secret: "s3cr3t", File: "b.js", Line: 10, Column: 1, Severity: SeverityLow},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings (one per file), got %d", len(deduped))
	}
	if deduped[0].File != "a.js" || deduped[1].File != "b.js" {
		t.Errorf("got files %q, %q; want a.js, b.js (stable File order)", deduped[0].File, deduped[1].File)
	}
}

func TestDeduplicateBySecretRuleNameIsSingleName(t *testing.T) {
	findings := []Finding{
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityLow},
		{RuleName: "r2", Secret: "s3cr3t", File: "a.js", Line: 10, Column: 1, Severity: SeverityHigh},
		{RuleName: "r1", Secret: "s3cr3t", File: "a.js", Line: 20, Column: 5, Severity: SeverityLow},
		{RuleName: "r2", Secret: "s3cr3t", File: "a.js", Line: 20, Column: 5, Severity: SeverityMedium},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) == 0 {
		t.Fatal("expected findings, got none")
	}
	for _, f := range deduped {
		if strings.Contains(f.RuleName, ",") {
			t.Errorf("RuleName = %q contains comma; must be a single exact name", f.RuleName)
		}
	}
}
