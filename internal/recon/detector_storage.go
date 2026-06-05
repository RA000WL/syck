package recon

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var storageHostRE = regexp.MustCompile(`(?i)([a-z0-9.-]+\.)?(s3\.amazonaws\.com|s3\.[a-z0-9-]+\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|storage\.cloud\.google\.com)`)
var storagePathRE = regexp.MustCompile(`(?i)/(s3|bucket|blob|storage)/`)

type StorageDetector struct{}

func (StorageDetector) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, u := range urls {
		if storageHostRE.MatchString(u) || storagePathRE.MatchString(u) {
			out = append(out, SurfaceFinding{
				URL:      u,
				Category: "storage",
				Severity: finding.SeverityHigh,
			})
		}
	}
	return out
}
