package scanner

import (
	"encoding/base64"
	"testing"

	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/finding"
)

const confidenceTestRules = "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"

func confidenceTestConfig(t *testing.T, decoders bool) Config {
	t.Helper()
	rs := loadTestRuleSet(t, confidenceTestRules)
	return Config{
		Rules:        rs,
		MinSeverity:  finding.ParseSeverity("LOW"),
		DecodeBase64: decoders,
	}
}

func TestConfidenceBandMatchesUnifiedScale(t *testing.T) {
	cfg := confidenceTestConfig(t, false)
	got := ScanContent("password = abcdef0123456789abcdef0123456789abcdef01", "x.txt", cfg)
	var entropyFindings []finding.Finding
	for _, f := range got {
		if f.DetectionMethod == "entropy+context" {
			entropyFindings = append(entropyFindings, f)
		}
	}
	if len(entropyFindings) == 0 {
		t.Fatalf("expected at least one entropy+context finding, got %d total findings", len(got))
	}
	want := confidence.PtsEntropy + confidence.PtsContext
	for _, f := range entropyFindings {
		if f.Confidence != want {
			t.Errorf("Confidence = %d, want %d (PtsEntropy+PtsContext)", f.Confidence, want)
		}
		if f.ConfidenceBand != confidence.Band(want) {
			t.Errorf("ConfidenceBand = %q, want %q (Band(%d))", f.ConfidenceBand, confidence.Band(want), want)
		}
	}
}

func TestNoFindingUsesLegacyScale(t *testing.T) {
	cfg := confidenceTestConfig(t, true)
	decodedPayload := base64.StdEncoding.EncodeToString([]byte("api_key=TOKEN_ABCDEF12;extra-padding-data-12345"))
	content := "api_key = \"TOKEN_ABCDEF12\"\n" +
		"password = abcdef0123456789abcdef0123456789abcdef01\n" +
		"config = \"" + decodedPayload + "\"\n"
	got := ScanContent(content, "x.txt", cfg)
	if len(got) == 0 {
		t.Fatalf("expected findings from mixed fixture, got none")
	}
	seenMethod := map[string]bool{}
	for _, f := range got {
		seenMethod[f.DetectionMethod] = true
		if f.Confidence > confidence.MaxScore {
			t.Errorf("Confidence = %d exceeds MaxScore %d (rule=%s method=%s)",
				f.Confidence, confidence.MaxScore, f.RuleName, f.DetectionMethod)
		}
		if f.ConfidenceBand != confidence.Band(f.Confidence) {
			t.Errorf("ConfidenceBand = %q, want Band(%d) = %q (rule=%s method=%s)",
				f.ConfidenceBand, f.Confidence, confidence.Band(f.Confidence), f.RuleName, f.DetectionMethod)
		}
	}
	for _, method := range []string{"regex", "entropy+context", "decoded_regex"} {
		if !seenMethod[method] {
			t.Errorf("expected at least one %q finding in mixed fixture, methods seen: %v", method, seenMethod)
		}
	}
}
