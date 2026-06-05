package correlation

import "github.com/RA000WL/syck/internal/finding"

type JWTKeyDetector struct{ MaxLineSpan int }

func (d JWTKeyDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 20
	}
	return matchPair(findings, "jwt", "jwt_signing_key", "jwt_key_pair", d.MaxLineSpan)
}
