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

		// The placeholder check is against the SECRET, not the context line.
		//
		// It was `placeholderRe.MatchString(f.Context)` originally, which was
		// the bug: Context is the whole source line, so any unrelated use of the
		// word "example" anywhere on that line demoted the finding to INFO —
		// below the default --severity floor. A JS object with
		// `example: "https://example.com/docs"` beside a live Stripe key
		// reported that key at INFO instead of CRITICAL.
		//
		// The intent is "the matched value is itself a placeholder", which is a
		// property of the secret. Checking Secret keeps that: `DB_PASSWORD=changeme`
		// still demotes, because the match carries `changeme`. Checking Context
		// also over-reached the directory-based step above, which is the
		// defensible one — a key in a test/ directory really is less likely to
		// be production, whereas a word on a nearby line says nothing about the
		// value.
		if sev > finding.SeverityInfo && placeholderRe.MatchString(f.Secret) {
			sev = finding.SeverityInfo
		}

		if sev != f.Severity {
			f.Severity = sev
		}
		out = append(out, f)
	}
	return out
}
