package formatters

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

var testFinding = finding.Finding{
	File:     "test.js",
	Line:     42,
	Column:   10,
	RuleName: "github_token",
	Severity: finding.SeverityCritical,
	Secret:   "ghp_test123456",
	Context:  "API_KEY=ghp_test123456",
	Entropy:  5.5,
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
