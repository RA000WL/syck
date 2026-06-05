package correlation

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestCorrelatorAllDetectorsPositive(t *testing.T) {
	c := NewCorrelator()
	c.RegisterDetector(AWSDetector{})
	c.RegisterDetector(StripeDetector{})
	c.RegisterDetector(TwilioDetector{})
	c.RegisterDetector(CloudflareDetector{})
	c.RegisterDetector(GitHubAppDetector{})
	c.RegisterDetector(OAuthDetector{})
	c.RegisterDetector(DatabaseURLDetector{})
	c.RegisterDetector(JWTKeyDetector{})

	findings := []finding.Finding{
		{RuleName: "aws_access_key_id", File: "f", Line: 1},
		{RuleName: "aws_secret_access_key", File: "f", Line: 2},
		{RuleName: "stripe_secret_key", File: "f", Line: 50},
		{RuleName: "stripe_publishable_key", File: "f", Line: 51},
		{RuleName: "twilio_account_sid", File: "f", Line: 100},
		{RuleName: "twilio_auth_token", File: "f", Line: 101},
		{RuleName: "cloudflare_email", File: "f", Line: 200},
		{RuleName: "cloudflare_api_key", File: "f", Line: 201},
		{RuleName: "github_app_id", File: "f", Line: 300},
		{RuleName: "github_app_private_key", File: "f", Line: 301},
		{RuleName: "oauth_client_id", File: "f", Line: 400},
		{RuleName: "oauth_client_secret", File: "f", Line: 401},
		{RuleName: "jwt", File: "f", Line: 500},
		{RuleName: "jwt_signing_key", File: "f", Line: 501},
		{RuleName: "database_url", File: "f", Line: 600, Secret: "postgres://user:pass@host:5432/db"},
	}
	got := c.Correlate(findings)
	if len(got) != 8 {
		t.Errorf("Correlate returned %d findings, want 8", len(got))
	}
	for _, c := range got {
		if c.Confidence != "VERY_HIGH" {
			t.Errorf("CorrelatedFinding %s confidence = %q, want VERY_HIGH", c.Type, c.Confidence)
		}
	}
}
