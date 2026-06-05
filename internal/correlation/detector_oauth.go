package correlation

import "github.com/RA000WL/syck/internal/finding"

type OAuthDetector struct{ MaxLineSpan int }

func (d OAuthDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 20
	}
	return matchPair(findings, "oauth_client_id", "oauth_client_secret", "oauth_credential_pair", d.MaxLineSpan)
}
