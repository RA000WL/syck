package finding

import "testing"

func TestFindingConfidenceField(t *testing.T) {
	f := Finding{
		RuleName:   "x",
		Severity:   SeverityHigh,
		Confidence: "HIGH",
	}
	if f.Confidence != "HIGH" {
		t.Errorf("Confidence = %q, want HIGH", f.Confidence)
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
