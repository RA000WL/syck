package correlation

import "github.com/RA000WL/syck/internal/finding"

type CloudflareDetector struct{ MaxLineSpan int }

func (d CloudflareDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 10
	}
	return matchPair(findings, "cloudflare_email", "cloudflare_api_key", "cloudflare_credential_pair", d.MaxLineSpan)
}
