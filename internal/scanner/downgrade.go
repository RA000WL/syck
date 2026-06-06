package scanner

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

var nonProdPaths = map[string]bool{
	"test": true, "tests": true, "spec": true, "specs": true, "__tests__": true,
	"example": true, "examples": true, "demo": true, "demos": true, "samples": true,
	"dummy": true, "mock": true, "mocks": true, "fixtures": true, "fixture": true,
	"stubs": true, "vendor": true, "third_party": true,
}

var placeholderRe = regexp.MustCompile(
	`(?i)\b(?:example|placeholder|changeme|change_me|your[-_](?:key|secret|token|password)|sample|TODO|FIXME|xxxxx|yyyyy|test[-_]?value|dummy)\b`,
)

func DowngradeFP(findings []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		sev := f.Severity

		dir := filepath.Dir(f.File)
		for _, part := range strings.Split(dir, string(filepath.Separator)) {
			if nonProdPaths[part] {
				if sev > finding.SeverityInfo {
					sev--
				}
				break
			}
		}

		if sev > finding.SeverityInfo && placeholderRe.MatchString(f.Context) {
			sev = finding.SeverityInfo
		}

		if sev != f.Severity {
			f.Severity = sev
		}
		out = append(out, f)
	}
	return out
}
