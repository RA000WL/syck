package scanner

import (
	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
)

// newScanCorrelator builds the detector set the active scan path runs.
//
// All eight detectors are registered, but only three can fire under the
// current ruleset: CloudflareDetector, GitHubAppDetector, JWTKeyDetector and
// OAuthDetector key off component rule names that exist in neither
// builtin.yaml (cloudflare_email/cloudflare_api_key, github_app_id/
// github_app_private_key, jwt/jwt_signing_key, oauth_client_id/
// oauth_client_secret), so no scan path can produce a component for them to
// match. Registering them anyway costs one map-free pass per detector and means
// those pairs start being reported the day the missing rule sets are added,
// with no edit here. Pinned by TestComponentRulesExistForEachDetector.
func newScanCorrelator() *correlation.Correlator {
	c := correlation.NewCorrelator()
	c.RegisterDetector(correlation.AWSDetector{})
	c.RegisterDetector(correlation.StripeDetector{})
	c.RegisterDetector(correlation.TwilioDetector{})
	c.RegisterDetector(correlation.CloudflareDetector{})
	c.RegisterDetector(correlation.GitHubAppDetector{})
	c.RegisterDetector(correlation.JWTKeyDetector{})
	c.RegisterDetector(correlation.OAuthDetector{})
	c.RegisterDetector(correlation.DatabaseURLDetector{})
	return c
}

// correlateFindings runs the credential-pair detectors over a completed
// collection of findings and appends the pairs it finds. Findings only ever go
// up: the two components are left exactly as they were.
//
// It is called once per scan at the collection boundary, not per file, and it
// applies cfg.MinSeverity itself. That last part is the whole reason this
// function exists rather than a plain call to Correlate: the rule paths gate on
// MinSeverity while they match (helpers.go:547 and the sub-scanner calls), so
// anything appended after collection would sail straight past --severity.
func correlateFindings(cfg Config, findings []finding.Finding) []finding.Finding {
	if cfg.NoCorrelation || len(findings) == 0 {
		return findings
	}

	c := newScanCorrelator()
	var pairs []finding.Finding
	for _, group := range groupByFile(findings) {
		for _, cf := range c.Correlate(group) {
			f := correlatedFinding(cf)
			if f.Severity < cfg.MinSeverity {
				continue
			}
			pairs = append(pairs, f)
		}
	}
	return append(findings, pairs...)
}

// groupByFile splits findings into per-file groups, preserving first-appearance
// order.
//
// This is a cost bound, not a behaviour change. matchPair refuses any pair
// whose components are in different files (internal/correlation/helpers.go:18)
// and DatabaseURLDetector judges one finding at a time, so correlating per
// group yields exactly the pairs a single call over the whole set would —
// while the quadratic component scan stays inside one file instead of spanning
// the entire scan. Measured on a 50k-finding collection with the rule names
// spread as in a real scan, one call is ~3.2ms; with 50k findings that all share
// one component rule name it is ~22s, and grouping removes that shape.
// TestGroupByFileMatchesSingleCall pins the equivalence.
func groupByFile(findings []finding.Finding) [][]finding.Finding {
	index := make(map[string]int, len(findings))
	var groups [][]finding.Finding
	for _, f := range findings {
		i, ok := index[f.File]
		if !ok {
			i = len(groups)
			index[f.File] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], f)
	}
	return groups
}

// correlatedFinding converts one correlated finding into an ordinary Finding so
// it travels the same output path — formatters, --diff, --validate, the cache —
// as everything else.
//
// The three fields worth explaining:
//
//   - Severity is max(component severities), not a constant and not the zero
//     value. finding.Finding's zero Severity is SeverityInfo, which is a real
//     severity below the CLI's default --severity LOW floor, so a pair that
//     derived nothing would be invisible by default. Deriving from the
//     components also keeps the pair honest as the component rules' severities
//     are tuned: retune twilio_account_sid and the pair follows.
//   - ConfidenceBand is confidence.Band(max component confidence score).
//     matchPair stamps a Confidence string of "VERY_HIGH", which the scorer
//     cannot produce for an in-range score, so passing that literal through
//     would put a sixth band into a field users sort and filter by. The band is
//     therefore always re-derived from a number.
//   - Secret and Context are both the detector's description. That is not a
//     matched value, and Context deliberately carries no raw source text: the
//     redactor masks Secret inside Context (internal/formatters/text.go:70), so
//     a Context holding the matched line would leak that secret under --redact.
//     The pair's position still points at the first component, and the
//     components themselves are reported alongside it.
func correlatedFinding(cf correlation.CorrelatedFinding) finding.Finding {
	out := finding.Finding{
		File:            cf.File,
		Line:            cf.Line,
		RuleName:        cf.Type,
		Secret:          cf.Description,
		Context:         cf.Description,
		DetectionMethod: "correlation",
		Severity:        finding.SeverityInfo,
	}
	for _, comp := range cf.Components {
		if comp.Severity > out.Severity {
			out.Severity = comp.Severity
		}
		if comp.Confidence > out.Confidence {
			out.Confidence = comp.Confidence
		}
	}
	if len(cf.Components) > 0 {
		out.Column = cf.Components[0].Column
	}
	out.ConfidenceBand = confidence.Band(out.Confidence)
	return out
}
