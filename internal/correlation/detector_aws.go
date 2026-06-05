package correlation

import "github.com/RA000WL/syck/internal/finding"

type AWSDetector struct{ MaxLineSpan int }

func (d AWSDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 20
	}
	return matchPair(findings, "aws_access_key_id", "aws_secret_access_key", "aws_credential_pair", d.MaxLineSpan)
}
