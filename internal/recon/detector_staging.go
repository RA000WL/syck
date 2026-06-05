package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var stagingRE = regexp.MustCompile(`(?i)/(staging|stg|uat|sit|preprod|dev|test)(\b|[-.]|$)`)
var stagingHostRE = regexp.MustCompile(`(?i)(staging|stg|uat|preprod|dev|test)([.-])`)

type StagingDetector struct{}

func (StagingDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if stagingRE.MatchString(u) || stagingHostRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "staging",
				Severity: finding.SeverityLow,
			})
		}
	}
	return out
}
