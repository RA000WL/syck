package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestGitHubAppDetectorPositive(t *testing.T) {
	d := GitHubAppDetector{}
	findings := []finding.Finding{
		{RuleName: "github_app_id", File: "f", Line: 1},
		{RuleName: "github_app_private_key", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "github_app_credential_pair" {
		t.Errorf("Type = %q, want github_app_credential_pair", got[0].Type)
	}
}

func TestGitHubAppDetectorNegative(t *testing.T) {
	d := GitHubAppDetector{}
	findings := []finding.Finding{{RuleName: "github_app_id", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
