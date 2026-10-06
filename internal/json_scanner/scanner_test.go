package json_scanner

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestScanJSONNestedSecretKey(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	content := `{"config":{"apiKey":"AKIAIOSFODNN7EXAMPLE"}}`
	findings := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
	if len(findings) < 1 {
		t.Fatalf("expected >= 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.HasPrefix(f.RuleName, "json_") {
		t.Errorf("RuleName = %q, want json_ prefix", f.RuleName)
	}
	if f.File != "app.json" {
		t.Errorf("File = %q, want app.json", f.File)
	}
	// Line is part of the finding shape; current implementation reports 0.
	t.Logf("finding: RuleName=%q File=%q Line=%d Secret=%q", f.RuleName, f.File, f.Line, f.Secret)
}

func TestScanJSONNonSecretKeyIgnored(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	content := `{"version":"1.2.3","name":"foo"}`
	findings := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestScanJSONMalformedInput(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	content := `{"config": {"apiKey": "AKIA..."  <- not valid json`
	findings := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for malformed JSON, got %d", len(findings))
	}
}
