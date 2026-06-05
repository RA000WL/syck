package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestJWTKeyDetectorPositive(t *testing.T) {
	d := JWTKeyDetector{}
	findings := []finding.Finding{
		{RuleName: "jwt", File: "f", Line: 1},
		{RuleName: "jwt_signing_key", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "jwt_key_pair" {
		t.Errorf("Type = %q, want jwt_key_pair", got[0].Type)
	}
}

func TestJWTKeyDetectorNegative(t *testing.T) {
	d := JWTKeyDetector{}
	findings := []finding.Finding{{RuleName: "jwt", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
