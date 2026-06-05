package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestOAuthDetectorPositive(t *testing.T) {
	d := OAuthDetector{}
	findings := []finding.Finding{
		{RuleName: "oauth_client_id", File: "f", Line: 1},
		{RuleName: "oauth_client_secret", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "oauth_credential_pair" {
		t.Errorf("Type = %q, want oauth_credential_pair", got[0].Type)
	}
}

func TestOAuthDetectorNegative(t *testing.T) {
	d := OAuthDetector{}
	findings := []finding.Finding{{RuleName: "oauth_client_id", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
