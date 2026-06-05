package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var debugRE = regexp.MustCompile(`(?i)/(debug|trace|diag|diagnostic|healthz|readyz|livez)(\b|/|$)`)

type DebugDetector struct{}

func (DebugDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if debugRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "debug",
				Severity: finding.SeverityLow,
			})
		}
	}
	return out
}
