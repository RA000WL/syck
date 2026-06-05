package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var adminRE = regexp.MustCompile(`(?i)/(admin|administrator|manage|management|panel|console)(\b|/|$)`)

type AdminDetector struct{}

func (AdminDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if adminRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "admin",
				Severity: finding.SeverityHigh,
			})
		}
	}
	return out
}
