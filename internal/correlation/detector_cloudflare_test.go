package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestCloudflareDetectorPositive(t *testing.T) {
	d := CloudflareDetector{}
	findings := []finding.Finding{
		{RuleName: "cloudflare_email", File: "f", Line: 1},
		{RuleName: "cloudflare_api_key", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "cloudflare_credential_pair" {
		t.Errorf("Type = %q, want cloudflare_credential_pair", got[0].Type)
	}
}

func TestCloudflareDetectorNegative(t *testing.T) {
	d := CloudflareDetector{}
	findings := []finding.Finding{{RuleName: "cloudflare_email", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
