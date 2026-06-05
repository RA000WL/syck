package correlation

import "github.com/RA000WL/syck/internal/finding"

type TwilioDetector struct{ MaxLineSpan int }

func (d TwilioDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 10
	}
	return matchPair(findings, "twilio_account_sid", "twilio_auth_token", "twilio_credential_pair", d.MaxLineSpan)
}
