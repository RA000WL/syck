package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestWiringDetectorRegistration(t *testing.T) {
	c := NewCorrelator()
	c.RegisterDetector(AWSDetector{})
	c.RegisterDetector(DatabaseURLDetector{})

	findings := []finding.Finding{
		{RuleName: "aws_access_key_id", File: "f", Line: 1},
		{RuleName: "aws_secret_access_key", File: "f", Line: 5},
		{RuleName: "random_other", File: "f", Line: 10},
		{RuleName: "dburl", File: "f", Line: 20, Secret: "postgres://a:b@host/db"},
	}
	got := c.Correlate(findings)
	if len(got) != 2 {
		t.Errorf("Correlate returned %d, want 2 (aws pair + dburl)", len(got))
	}
}
