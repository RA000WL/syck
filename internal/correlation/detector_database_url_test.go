package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestDatabaseURLDetectorPositive(t *testing.T) {
	d := DatabaseURLDetector{}
	findings := []finding.Finding{
		{RuleName: "database_url", File: "f", Line: 1, Secret: "postgres://user:pass@host:5432/db"},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "database_url_with_credentials" {
		t.Errorf("Type = %q, want database_url_with_credentials", got[0].Type)
	}
}

func TestDatabaseURLDetectorNegative(t *testing.T) {
	d := DatabaseURLDetector{}
	findings := []finding.Finding{
		{RuleName: "some_other", File: "f", Line: 1, Secret: "just a normal string"},
	}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
