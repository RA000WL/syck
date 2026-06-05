package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestAWSDetectorPositive(t *testing.T) {
	d := AWSDetector{}
	findings := []finding.Finding{
		{RuleName: "aws_access_key_id", File: "f", Line: 1},
		{RuleName: "aws_secret_access_key", File: "f", Line: 2},
	}
	got := d.Match(findings)
	if len(got) != 1 {
		t.Errorf("Match returned %d, want 1", len(got))
	}
	if got[0].Type != "aws_credential_pair" {
		t.Errorf("Type = %q, want aws_credential_pair", got[0].Type)
	}
}

func TestAWSDetectorNegative(t *testing.T) {
	d := AWSDetector{}
	findings := []finding.Finding{{RuleName: "aws_access_key_id", File: "f", Line: 1}}
	got := d.Match(findings)
	if len(got) != 0 {
		t.Errorf("Match returned %d, want 0", len(got))
	}
}
