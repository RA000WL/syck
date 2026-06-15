package formatters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestJSONLFormatter_OneLinePerFinding(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test_rule", Severity: finding.SeverityHigh, Secret: "abc123", Line: 1},
		{File: "b.js", RuleName: "test_rule2", Severity: finding.SeverityCritical, Secret: "xyz789", Line: 5},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %s", len(lines), output)
	}

	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d: not valid JSON: %v", i, err)
		}
	}
}

func TestJSONLFormatter_NoWrappingArray(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test", Severity: finding.SeverityLow, Secret: "x", Line: 1},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	output = strings.TrimSpace(output)
	if strings.HasPrefix(output, "[") {
		t.Error("JSONL should not start with array bracket")
	}
}

func TestJSONLFormatter_EmptyFindings(t *testing.T) {
	f := &JSONLFormatter{}
	output, err := f.Format(nil, FormatOptions{NoColor: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output) != "" {
		t.Errorf("expected empty output, got %q", output)
	}
}

func TestJSONLFormatter_Redact(t *testing.T) {
	findings := []finding.Finding{
		{File: "a.js", RuleName: "test", Severity: finding.SeverityHigh, Secret: "supersecret123", Line: 1},
	}
	f := &JSONLFormatter{}
	output, err := f.Format(findings, FormatOptions{NoColor: true, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "supersecret123") {
		t.Error("secret should be redacted")
	}
}
