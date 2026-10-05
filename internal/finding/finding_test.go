package finding

import "testing"

func TestParseSeverityCaseInsensitive(t *testing.T) {
	if ParseSeverity("critical") != SeverityCritical {
		t.Fatal("lowercase critical")
	}
	if ParseSeverity("High") != SeverityHigh {
		t.Fatal("mixed high")
	}
	if ParseSeverity("MEDIUM") != SeverityMedium {
		t.Fatal("upper medium")
	}
	if ParseSeverity("bogus") != SeverityLow {
		t.Fatal("unknown fallback")
	}
}

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

func TestDeduplicateBySecret(t *testing.T) {
	findings := []Finding{
		{RuleName: "google_api_key", Secret: "AIzaSy123", File: "a.js", Severity: SeverityHigh},
		{RuleName: "generic_secret", Secret: "AIzaSy123", File: "a.js", Severity: SeverityHigh},
		{RuleName: "api_key_header", Secret: "AIzaSy123", File: "a.js", Severity: SeverityHigh},
		{RuleName: "high_entropy_token", Secret: "AIzaSy123", File: "a.js", Severity: SeverityMedium},
		{RuleName: "url_google_api_key", Secret: "AIzaSy123", File: "a.js", Severity: SeverityHigh},
		{RuleName: "google_api_key", Secret: "OTHERSECRET", File: "b.js", Severity: SeverityCritical},
	}
	deduped := DeduplicateBySecret(findings)
	// AIzaSy123: 5 findings → 1 (highest severity kept, all rules recorded)
	// OTHERSECRET: 1 finding → 1
	// Total: 2
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(deduped))
	}

	// Find the AIzaSy123 entry
	var aiFound, otherFound bool
	for _, f := range deduped {
		if f.Secret == "AIzaSy123" {
			aiFound = true
			// Single exact rule name: highest severity wins, ties by name asc.
			// All 5 findings share Line 0/Column 0 (one occurrence), so
			// RuleNames records all 5 rules, severity desc then name asc.
			if f.RuleName != "api_key_header" {
				t.Errorf("AIzaSy123 RuleName = %q, want %q (single highest-severity name)", f.RuleName, "api_key_header")
			}
			wantNames := []string{"api_key_header", "generic_secret", "google_api_key", "url_google_api_key", "high_entropy_token"}
			if len(f.RuleNames) != len(wantNames) {
				t.Errorf("AIzaSy123 RuleNames = %q, want %q", f.RuleNames, wantNames)
			} else {
				for i, want := range wantNames {
					if f.RuleNames[i] != want {
						t.Errorf("AIzaSy123 RuleNames[%d] = %q, want %q (full: %q)", i, f.RuleNames[i], want, f.RuleNames)
					}
				}
			}
			// Should keep highest severity (HIGH, not MEDIUM)
			if f.Severity != SeverityHigh {
				t.Errorf("AIzaSy123 Severity = %v, want SeverityHigh", f.Severity)
			}
		}
		if f.Secret == "OTHERSECRET" {
			otherFound = true
			if f.Severity != SeverityCritical {
				t.Errorf("OTHERSECRET Severity = %v, want SeverityCritical", f.Severity)
			}
		}
	}
	if !aiFound {
		t.Error("AIzaSy123 finding missing")
	}
	if !otherFound {
		t.Error("OTHERSECRET finding missing")
	}
}

func TestDeduplicateBySecret_SameFileDifferentSecrets(t *testing.T) {
	findings := []Finding{
		{RuleName: "rule_a", Secret: "secret1", File: "a.js", Severity: SeverityHigh},
		{RuleName: "rule_b", Secret: "secret2", File: "a.js", Severity: SeverityCritical},
	}
	deduped := DeduplicateBySecret(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings (different secrets), got %d", len(deduped))
	}
}

func TestDeduplicateBySecret_SameSecretDifferentFiles(t *testing.T) {
	findings := []Finding{
		{RuleName: "rule_a", Secret: "secret1", File: "a.js", Severity: SeverityHigh},
		{RuleName: "rule_b", Secret: "secret1", File: "b.js", Severity: SeverityMedium},
	}
	deduped := DeduplicateBySecret(findings)
	// Different files, same secret → should be deduped (same key = secret+file)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings (different files), got %d", len(deduped))
	}
}
