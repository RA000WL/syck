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

// The reported rule owns the whole reported finding: Confidence, band, entropy
// and detection method must come from the rule being named, not from whichever
// rule happened to be seen first. ConfidenceBand is a triage field keyed off
// RuleName, so mixing the two is incoherent.
func TestDeduplicateBySecretRepresentativeComesFromReportedRule(t *testing.T) {
	findings := []Finding{
		{
			RuleName: "dotenv_file_secret", Secret: "AKIAIOSFODNN7EXAMPLE",
			File: "a.env", Line: 4, Column: 2, Severity: SeverityMedium,
			Entropy: 4.10, Confidence: 35, ConfidenceBand: "MEDIUM",
			DetectionMethod: "entropy+context",
		},
		{
			RuleName: "aws_access_key_id", Secret: "AKIAIOSFODNN7EXAMPLE",
			File: "a.env", Line: 4, Column: 2, Severity: SeverityHigh,
			Entropy: 3.80, Confidence: 95, ConfidenceBand: "CRITICAL",
			DetectionMethod: "regex",
		},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding (one occurrence), got %d", len(deduped))
	}
	got := deduped[0]
	if got.RuleName != "aws_access_key_id" {
		t.Errorf("RuleName = %q, want aws_access_key_id (highest severity)", got.RuleName)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("Severity = %v, want SeverityHigh", got.Severity)
	}
	if got.Confidence != 95 {
		t.Errorf("Confidence = %d, want 95 (from the HIGH rule's own finding, not 35)", got.Confidence)
	}
	if got.ConfidenceBand != "CRITICAL" {
		t.Errorf("ConfidenceBand = %q, want CRITICAL (HIGH rule's own band, not MEDIUM)", got.ConfidenceBand)
	}
	if got.DetectionMethod != "regex" {
		t.Errorf("DetectionMethod = %q, want regex (HIGH rule's own method, not entropy+context)", got.DetectionMethod)
	}
	if got.Entropy != 3.80 {
		t.Errorf("Entropy = %v, want 3.8 (HIGH rule's own entropy)", got.Entropy)
	}
	if len(got.RuleNames) != 2 || got.RuleNames[0] != "aws_access_key_id" || got.RuleNames[1] != "dotenv_file_secret" {
		t.Errorf("RuleNames = %q, want [aws_access_key_id dotenv_file_secret]", got.RuleNames)
	}
}

// Ties keep the first-seen finding for that rule name.
func TestDeduplicateBySecretRepresentativeTieKeepsFirstSeen(t *testing.T) {
	findings := []Finding{
		{RuleName: "r1", Secret: "s", File: "a.js", Line: 1, Column: 1, Severity: SeverityHigh, Confidence: 10, DetectionMethod: "first"},
		{RuleName: "r1", Secret: "s", File: "a.js", Line: 1, Column: 1, Severity: SeverityHigh, Confidence: 20, DetectionMethod: "second"},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(deduped))
	}
	if deduped[0].DetectionMethod != "first" {
		t.Errorf("DetectionMethod = %q, want first (tie keeps first seen)", deduped[0].DetectionMethod)
	}
}
