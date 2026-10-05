package formatters

import (
	"strconv"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

// countRenderedFindings counts the per-finding lines the text formatter emits.
// Each finding is printed as "  <icon> <SEVERITY> ..."; context lines are
// indented four spaces and the category/summary blocks use box-drawing
// characters or bare labels, so the severity icons are an unambiguous marker.
func countRenderedFindings(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		for _, icon := range sevIcon {
			if strings.HasPrefix(trimmed, icon) {
				n++
				break
			}
		}
	}
	return n
}

func summaryTotal(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "  Total findings") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			break
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			break
		}
		return n
	}
	return -1
}

// threeOccurrenceFixture: one secret on three lines, matched by two rules.
func threeOccurrenceFixture() []finding.Finding {
	return []finding.Finding{
		{File: "app.env", Line: 1, Column: 1, RuleName: "dotenv_file_secret", Severity: finding.SeverityMedium, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "KEY=AKIAIOSFODNN7EXAMPLE"},
		{File: "app.env", Line: 2, Column: 1, RuleName: "dotenv_file_secret", Severity: finding.SeverityMedium, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "KEY=AKIAIOSFODNN7EXAMPLE"},
		{File: "app.env", Line: 3, Column: 1, RuleName: "aws_access_key_id", Severity: finding.SeverityHigh, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "KEY=AKIAIOSFODNN7EXAMPLE"},
	}
}

func TestTextFormatterRendersEveryOccurrence(t *testing.T) {
	deduped := finding.DeduplicateBySecret(threeOccurrenceFixture())
	if len(deduped) != 3 {
		t.Fatalf("DeduplicateBySecret returned %d findings, want 3 (one per occurrence)", len(deduped))
	}

	out, err := (&TextFormatter{}).Format(deduped, FormatOptions{NoColor: true, Quiet: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	// (a) the formatter must not re-collapse per-secret
	if got := countRenderedFindings(out); got != 3 {
		t.Errorf("rendered %d findings, want 3 (formatter re-collapsed per secret)\n%s", got, out)
	}

	// (b) each occurrence must be locatable
	for _, loc := range []string{"app.env:1:1", "app.env:2:1", "app.env:3:1"} {
		if !strings.Contains(out, loc) {
			t.Errorf("text output missing location %q\n%s", loc, out)
		}
	}
}

func TestTextSummaryMatchesRenderedCount(t *testing.T) {
	deduped := finding.DeduplicateBySecret(threeOccurrenceFixture())
	out, err := (&TextFormatter{}).Format(deduped, FormatOptions{NoColor: true, Quiet: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	rendered := countRenderedFindings(out)
	if rendered != len(deduped) {
		t.Fatalf("rendered %d findings, input has %d\n%s", rendered, len(deduped), out)
	}
	// (c) the reported total must agree with what was printed
	if got := summaryTotal(out); got != rendered {
		t.Errorf("summary total = %d, rendered %d findings\n%s", got, rendered, out)
	}
}

func TestTextOutputCountMatchesBuildSummary(t *testing.T) {
	in := []finding.Finding{
		{File: "app.env", Line: 7, Column: 3, RuleName: "dotenv_file_secret", Severity: finding.SeverityHigh, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "KEY=AKIAIOSFODNN7EXAMPLE"},
		{File: "app.env", Line: 9, Column: 3, RuleName: "dotenv_file_secret", Severity: finding.SeverityHigh, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "KEY=AKIAIOSFODNN7EXAMPLE"},
	}
	out, err := (&TextFormatter{}).Format(in, FormatOptions{NoColor: true, Quiet: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	// (d) text and JSON must agree on how many findings exist
	if want := BuildSummary(in).TotalFindings; countRenderedFindings(out) != want {
		t.Errorf("rendered %d findings, BuildSummary reports %d\n%s", countRenderedFindings(out), want, out)
	}
}

func TestTextFormatterDoesNotCollapseAcrossRules(t *testing.T) {
	// Two rules matching the same secret on the same line stay one finding
	// (that collapse is the scanner's job, not the formatter's), but two
	// different files are two findings.
	in := []finding.Finding{
		{File: "a.env", Line: 1, Column: 1, RuleName: "aws_access_key_id", Severity: finding.SeverityHigh, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "x"},
		{File: "b.env", Line: 1, Column: 1, RuleName: "aws_access_key_id", Severity: finding.SeverityHigh, Secret: "AKIAIOSFODNN7EXAMPLE", Context: "x"},
	}
	out, err := (&TextFormatter{}).Format(in, FormatOptions{NoColor: true, Quiet: true})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if got := countRenderedFindings(out); got != 2 {
		t.Errorf("rendered %d findings, want 2 (one per file)\n%s", got, out)
	}
}
