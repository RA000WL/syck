package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestStripeDetectorPositive(t *testing.T) {
	d := StripeDetector{}
	findings := []finding.Finding{
		{RuleName: "stripe_secret_key", File: "f", Line: 1},
		{RuleName: "stripe_publishable_key", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "stripe_credential_pair" {
		t.Errorf("Type = %q, want stripe_credential_pair", got[0].Type)
	}
}

func TestStripeDetectorNegative(t *testing.T) {
	d := StripeDetector{}
	findings := []finding.Finding{{RuleName: "stripe_secret_key", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
