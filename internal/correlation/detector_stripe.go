package correlation

import "github.com/RA000WL/syck/internal/finding"

type StripeDetector struct{ MaxLineSpan int }

func (d StripeDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 50
	}
	return matchPair(findings, "stripe_secret_key", "stripe_publishable_key", "stripe_credential_pair", d.MaxLineSpan)
}
