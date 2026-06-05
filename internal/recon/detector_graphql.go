package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var graphqlRE = regexp.MustCompile(`(?i)(/graphql(\b|/|$)|/gql(\b|/|$))`)

type GraphQLDetector struct{}

func (GraphQLDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if graphqlRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "graphql",
				Severity: finding.SeverityHigh,
			})
		}
	}
	return out
}
