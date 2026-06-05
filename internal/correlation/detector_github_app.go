package correlation

import "github.com/RA000WL/syck/internal/finding"

type GitHubAppDetector struct{ MaxLineSpan int }

func (d GitHubAppDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	if d.MaxLineSpan == 0 {
		d.MaxLineSpan = 100
	}
	return matchPair(findings, "github_app_id", "github_app_private_key", "github_app_credential_pair", d.MaxLineSpan)
}
