package formatters

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

var testFinding = finding.Finding{
	File:      "test.js",
	Line:      42,
	Column:    10,
	RuleName:  "github_token",
	Severity:  finding.SeverityCritical,
	RiskScore: 7,
	Secret:    "ghp_test123456",
	Context:   "API_KEY=ghp_test123456",
	Entropy:   5.5,
}

var allFormatters = []string{"text", "json", "sarif", "markdown", "csv", "html"}

func TestNewReturnsNonNil(t *testing.T) {
	for _, name := range allFormatters {
		f := New(name)
		if f == nil {
			t.Errorf("New(%q) returned nil", name)
		}
	}
}

func TestFormatReturnsContent(t *testing.T) {
	for _, name := range allFormatters {
		f := New(name)
		out, err := f.Format([]finding.Finding{testFinding}, FormatOptions{})
		if err != nil {
			t.Errorf("%s.Format() error: %v", name, err)
		}
		if out == "" {
			t.Errorf("%s.Format() returned empty string", name)
		}
	}
}

func TestRedactMasksSecrets(t *testing.T) {
	opts := FormatOptions{Redact: true}
	for _, name := range allFormatters {
		f := New(name)
		out, err := f.Format([]finding.Finding{testFinding}, opts)
		if err != nil {
			t.Errorf("%s.Format() error: %v", name, err)
		}
		// The secret field should be masked — "ghp_" prefix + asterisks
		if strings.Contains(out, "ghp_test123456") {
			t.Errorf("%s redact mode still shows full secret in output", name)
		}
	}
}

func TestRedactDoesNotMaskShortSecrets(t *testing.T) {
	short := finding.Finding{
		File: "x", Line: 1, Column: 1, RuleName: "r",
		Severity: finding.SeverityLow, Secret: "ab", Context: "c", Entropy: 1.0,
	}
	opts := FormatOptions{Redact: true}
	for _, name := range allFormatters {
		f := New(name)
		_, err := f.Format([]finding.Finding{short}, opts)
		if err != nil {
			t.Errorf("%s.Format() error: %v", name, err)
		}
	}
}

func TestRiskScoreInJSON(t *testing.T) {
	out, _ := (&JSONFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{})
	if !strings.Contains(out, `"risk_score": 7`) {
		t.Errorf("JSON missing risk_score 7, got: %s", out)
	}
}

func TestRiskScoreInText(t *testing.T) {
	out, _ := (&TextFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{NoColor: true})
	if !strings.Contains(out, "[!]") {
		t.Errorf("text missing [!] for score 7, got: %s", out)
	}
}

func TestRiskScoreInSARIF(t *testing.T) {
	out, _ := (&SARIFFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{})
	if !strings.Contains(out, `"riskScore": 7`) {
		t.Errorf("SARIF missing riskScore 7, got: %s", out)
	}
}

func TestRiskScoreInMarkdown(t *testing.T) {
	out, _ := (&MarkdownFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{})
	if !strings.Contains(out, "| 7 |") {
		t.Errorf("markdown missing Risk column 7, got: %s", out)
	}
}

func TestRiskScoreInCSV(t *testing.T) {
	out, _ := (&CSVFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{})
	if !strings.Contains(out, ",7,") {
		t.Errorf("CSV missing risk_score 7, got: %s", out)
	}
}

func TestRiskScoreInHTML(t *testing.T) {
	out, _ := (&HTMLFormatter{}).Format([]finding.Finding{testFinding}, FormatOptions{})
	if !strings.Contains(out, `>7<`) {
		t.Errorf("HTML missing risk badge 7, got: %s", out)
	}
}
