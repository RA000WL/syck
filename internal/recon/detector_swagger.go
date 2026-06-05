package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var swaggerRE = regexp.MustCompile(`(?i)(/swagger\.(json|yaml|yml)|/api-docs|/openapi\.(json|yaml|yml))`)

type SwaggerDetector struct{}

func (SwaggerDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if swaggerRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "swagger",
				Severity: finding.SeverityMedium,
			})
		}
	}
	return out
}
