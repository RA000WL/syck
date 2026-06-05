package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var authRE = regexp.MustCompile(`(?i)/(login|oauth|token|authorize)(\b|/|$)`)

type AuthDetector struct{}

func (AuthDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if authRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "auth",
				Severity: finding.SeverityMedium,
			})
		}
	}
	return out
}
