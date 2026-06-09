package finding

import "testing"

func TestFindingConfidenceField(t *testing.T) {
	f := Finding{
		RuleName:       "x",
		Severity:       SeverityHigh,
		ConfidenceBand: "HIGH",
	}
	if f.ConfidenceBand != "HIGH" {
		t.Errorf("ConfidenceBand = %q, want HIGH", f.ConfidenceBand)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %v, want SeverityHigh", f.Severity)
	}
}

func TestFindingVerificationStatusField(t *testing.T) {
	f := Finding{VerificationStatus: "VERIFIED"}
	if f.VerificationStatus != "VERIFIED" {
		t.Errorf("VerificationStatus = %q, want VERIFIED", f.VerificationStatus)
	}
}

func TestFindingDecodedValuePreviewField(t *testing.T) {
	f := Finding{DecodedValuePreview: "hello"}
	if f.DecodedValuePreview != "hello" {
		t.Errorf("DecodedValuePreview = %q, want hello", f.DecodedValuePreview)
	}
}

func TestDeduplicate_ContextAware(t *testing.T) {
	f1 := Finding{RuleName: "test", Secret: "abc", File: "f.txt", Context: "line1: password=abc"}
	f2 := Finding{RuleName: "test", Secret: "abc", File: "f.txt", Context: "line2: password=abc"}
	f3 := Finding{RuleName: "test", Secret: "abc", File: "f.txt", Context: "line1: password=abc"}

	result := Deduplicate([]Finding{f1, f2, f3})
	if len(result) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(result))
	}
}
