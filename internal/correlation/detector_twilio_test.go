package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestTwilioDetectorPositive(t *testing.T) {
	d := TwilioDetector{}
	findings := []finding.Finding{
		{RuleName: "twilio_account_sid", File: "f", Line: 1},
		{RuleName: "twilio_auth_token", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "twilio_credential_pair" {
		t.Errorf("Type = %q, want twilio_credential_pair", got[0].Type)
	}
}

func TestTwilioDetectorNegative(t *testing.T) {
	d := TwilioDetector{}
	findings := []finding.Finding{{RuleName: "twilio_account_sid", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
