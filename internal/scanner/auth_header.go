package scanner

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
)

var (
	bearerTokenRe  = regexp.MustCompile(`(?i)(?:Authorization|auth)[\s:=]+['"]?(?:Bearer\s+)?([A-Za-z0-9\-_.+/=]{20,})['"]?`)
	basicAuthRe    = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{10,})`)
	apiKeyHeaderRe = regexp.MustCompile(`(?i)(?:X-)?API(?:Key|_Key|-Key)\s*[:=]\s*['"]?([A-Za-z0-9_\-+!@#$%^&*()=]{16,})['"]?`)
	authTokenRe    = regexp.MustCompile(`(?i)(?:X-)?Auth(?:Token|_Token|-Token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{16,})['"]?`)
)

func DetectAuthHeaders(line string, path string, lineNum int) []finding.Finding {
	var findings []finding.Finding

	if m := bearerTokenRe.FindStringSubmatch(line); len(m) >= 2 {
		token := m[len(m)-1]
		if len(token) >= 20 {
			findings = append(findings, finding.Finding{
				File: path, Line: lineNum,
				RuleName: "bearer_token_hardcoded",
				Severity: finding.SeverityHigh,
				Secret:   token,
				Context:  finding.Truncate(line),
			})
		}
	}

	if m := basicAuthRe.FindStringSubmatch(line); len(m) >= 2 {
		findings = append(findings, finding.Finding{
			File: path, Line: lineNum,
			RuleName: "basic_auth_hardcoded",
			Severity: finding.SeverityCritical,
			Secret:   m[1],
			Context:  finding.Truncate(line),
		})
	}

	if m := apiKeyHeaderRe.FindStringSubmatch(line); len(m) >= 2 {
		findings = append(findings, finding.Finding{
			File: path, Line: lineNum,
			RuleName: "api_key_header_hardcoded",
			Severity: finding.SeverityHigh,
			Secret:   m[1],
			Context:  finding.Truncate(line),
		})
	}

	if m := authTokenRe.FindStringSubmatch(line); len(m) >= 2 {
		findings = append(findings, finding.Finding{
			File: path, Line: lineNum,
			RuleName: "auth_token_header_hardcoded",
			Severity: finding.SeverityHigh,
			Secret:   m[1],
			Context:  finding.Truncate(line),
		})
	}

	return findings
}
