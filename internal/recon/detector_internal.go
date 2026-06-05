package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var internalRE = regexp.MustCompile(`(?i)/(internal|private|intranet|corp)(\b|/|$)`)
var internalHostRE = regexp.MustCompile(`(?i)(internal\.|corp\.|\.local)`)

type InternalDetector struct{}

func (InternalDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if internalRE.MatchString(u) || internalHostRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "internal",
				Severity: finding.SeverityLow,
			})
		}
	}
	return out
}
