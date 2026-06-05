package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var metricsRE = regexp.MustCompile(`(?i)/(metrics|prometheus|statsd|actuator)(\b|/|$)`)

type MetricsDetector struct{}

func (MetricsDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if metricsRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "metrics",
				Severity: finding.SeverityMedium,
			})
		}
	}
	return out
}
