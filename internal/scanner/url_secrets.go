package scanner

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
)

var urlSecretParams = map[string]string{
	"access_token": "url_access_token",
	"token":        "url_token",
	"apikey":       "url_api_key",
	"api_key":      "url_api_key",
	"auth":         "url_auth_token",
	"jwt":          "url_jwt",
	"bearer":       "url_bearer_token",
	"key":          "url_key",
	"secret":       "url_secret",
}

var urlRE = regexp.MustCompile(`https?://[^\s'"<>]+`)

func ExtractURLSecrets(line string, path string, lineno int) []finding.Finding {
	var findings []finding.Finding
	matches := urlRE.FindAllString(line, -1)
	for _, rawURL := range matches {
		rawURL = strings.TrimRight(rawURL, "',\")];}+")
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		params := parsed.Query()
		for param, ruleName := range urlSecretParams {
			if val := params.Get(param); val != "" && len(val) >= 16 {
				e := entropy.Shannon(val)
				if e < 2.0 {
					continue
				}
				findings = append(findings, finding.Finding{
					File:            path,
					Line:            lineno,
					Column:          0,
					RuleName:        ruleName,
					Severity:        finding.SeverityHigh,
					Secret:          val,
					Context:         finding.Truncate("URL secret param: " + param + "=" + val),
					Entropy:         e,
					Confidence:      finding.ConfidenceURLParam + finding.ConfidenceRegex,
					DetectionMethod: "url_param",
				})
			}
		}
	}
	return findings
}
