package correlation

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var dbURLRE = regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb|redis|amqp)(\+\w+)?://[^:]+:[^@]+@`)

type DatabaseURLDetector struct{}

func (d DatabaseURLDetector) Match(findings []finding.Finding) []CorrelatedFinding {
	var out []CorrelatedFinding
	for _, f := range findings {
		if !dbURLRE.MatchString(f.Secret) {
			continue
		}
		out = append(out, CorrelatedFinding{
			Type:        "database_url_with_credentials",
			Confidence:  "VERY_HIGH",
			Components:  []finding.Finding{f},
			File:        f.File,
			Line:        f.Line,
			Description: "Database URL contains embedded credentials",
		})
	}
	return out
}
