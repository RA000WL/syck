package formatters

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type HTMLFormatter struct{}

var sevBadgeColor = map[finding.Severity]string{
	finding.SeverityCritical: "#ff4444",
	finding.SeverityHigh:     "#ff8800",
	finding.SeverityMedium:   "#ffcc00",
	finding.SeverityLow:      "#888888",
	finding.SeverityInfo:     "#666666",
}

func (f *HTMLFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Syck Scan Results</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a2e;color:#e0e0e0;font-family:system-ui,-apple-system,sans-serif;padding:2rem}
.container{max-width:1200px;margin:0 auto}
h1{margin-bottom:.5rem;color:#fff}
.warning{background:#332200;border-left:4px solid #ffcc00;padding:.75rem 1rem;margin-bottom:1.5rem;border-radius:4px;color:#ffcc00}
h2{margin:1.5rem 0 .75rem;color:#ccc;font-size:1.1rem}
table{width:100%;border-collapse:collapse;margin-bottom:1.5rem}
th,td{padding:.5rem .75rem;text-align:left;border-bottom:1px solid #333;font-size:.9rem}
th{color:#aaa;font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:600;color:#fff}
.summary-box{background:#16213e;border:1px solid #333;border-radius:8px;padding:1rem 1.5rem;margin-top:1rem}
.summary-box p{margin:.25rem 0}
.secret-cell{font-family:monospace;word-break:break-all}
</style>
</head>
<body>
<div class="container">
<h1>Syck Scan Results</h1>
`)

	if !opts.Quiet {
		b.WriteString(`<div class="warning">WARNING: secrets are shown IN FULL — do not share this output publicly.</div>
`)
	}

	byFile := make(map[string][]finding.Finding)
	for _, f := range findings {
		cp := f
		if opts.Redact {
			cp.Secret = RedactSecret(f.Secret)
		}
		byFile[f.File] = append(byFile[f.File], cp)
	}

	for _, file := range sortedFiles(byFile) {
		ff := byFile[file]
		b.WriteString(fmt.Sprintf("<h2><code>%s</code></h2>\n", htmlEscape(file)))
		b.WriteString("<table>\n<tr><th>Line</th><th>Severity</th><th>Risk</th><th>Confidence</th><th>Verification</th><th>Rule</th><th>Entropy</th><th>Adapt</th><th>Tier</th><th>Decoded</th><th>Secret</th></tr>\n")
		for _, f := range ff {
			color := sevBadgeColor[f.Severity]
			riskBadge := ""
			if f.RiskScore >= 5 {
				riskColor := "#ff8800"
				if f.RiskScore >= 8 {
					riskColor = "#ff4444"
				}
				riskBadge = fmt.Sprintf(`<span class="badge" style="background:%s">%d</span>`, riskColor, f.RiskScore)
			}
			confBadge := ""
			if f.ConfidenceBand != "" {
				confBadge = fmt.Sprintf(`<span class="badge" style="background:%s">%s</span>`, confColor(f.ConfidenceBand), htmlEscape(f.ConfidenceBand))
			}
			verBadge := ""
			if f.VerificationStatus != "" {
				verBadge = fmt.Sprintf(`<span class="badge" style="background:%s">%s</span>`, verColor(f.VerificationStatus), htmlEscape(f.VerificationStatus))
			}
			decoded := ""
			if f.DecodedValuePreview != "" {
				decoded = fmt.Sprintf(`<details><summary>preview</summary><code>%s</code></details>`, htmlEscape(f.DecodedValuePreview))
			}
			adaptCell := "-"
			tierCell := "-"
			if f.AdaptiveModifier != 0 {
				adaptCell = fmt.Sprintf("%+d", f.AdaptiveModifier)
				tierCell = f.LearningTier
			}
			b.WriteString(fmt.Sprintf("<tr><td>%d</td><td><span class=\"badge\" style=\"background:%s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%.3f</td><td>%s</td><td>%s</td><td>%s</td><td class=\"secret-cell\"><code>%s</code></td></tr>\n",
				f.Line, color, finding.SeverityNames[f.Severity], riskBadge, confBadge, verBadge, htmlEscape(f.RuleName), f.Entropy, adaptCell, tierCell, decoded, htmlEscape(f.Secret)))
		}
		b.WriteString("</table>\n")
	}

	summary := BuildSummary(findings)
	b.WriteString(`<div class="summary-box">
`)
	b.WriteString(fmt.Sprintf("<p><strong>Files with findings:</strong> %d</p>\n", summary.FilesWithFindings))
	b.WriteString(fmt.Sprintf("<p><strong>Total findings:</strong> %d</p>\n", summary.TotalFindings))

	if summary.TotalFindings > 0 {
		b.WriteString("<h3>By Severity</h3><table>\n<tr><th>Severity</th><th>Count</th></tr>\n")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if count := summary.SeverityCounts[sev]; count > 0 {
				sv := finding.SeverityFromName[sev]
				color := sevBadgeColor[sv]
				b.WriteString(fmt.Sprintf("<tr><td><span class=\"badge\" style=\"background:%s\">%s</span></td><td>%d</td></tr>\n",
					color, sev, count))
			}
		}
		b.WriteString("</table>\n")

		if len(summary.FileTypeCounts) > 0 {
			b.WriteString("<h3>By File Type</h3><table>\n<tr><th>Extension</th><th>Count</th></tr>\n")
			exts := make([]string, 0, len(summary.FileTypeCounts))
			for ext := range summary.FileTypeCounts {
				exts = append(exts, ext)
			}
			sort.Strings(exts)
			for _, ext := range exts {
				b.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>%d</td></tr>\n", htmlEscape(ext), summary.FileTypeCounts[ext]))
			}
			b.WriteString("</table>\n")
		}

		if len(summary.RiskScoreDist) > 0 {
			b.WriteString("<h3>Risk Score Distribution</h3><table>\n<tr><th>Score</th><th>Count</th></tr>\n")
			scores := make([]int, 0, len(summary.RiskScoreDist))
			for s := range summary.RiskScoreDist {
				scores = append(scores, s)
			}
			sort.Ints(scores)
			for _, s := range scores {
				b.WriteString(fmt.Sprintf("<tr><td>%d</td><td>%d</td></tr>\n", s, summary.RiskScoreDist[s]))
			}
			b.WriteString("</table>\n")
		}

		if summary.EndpointCount > 0 {
			b.WriteString(fmt.Sprintf("<p><strong>Endpoints detected:</strong> %d</p>\n", summary.EndpointCount))
		}
	}

	b.WriteString("</div>\n</div>\n</body>\n</html>\n")

	return b.String(), nil
}

func confColor(confidence string) string {
	switch confidence {
	case "CRITICAL", "VERY_HIGH":
		return "#ff4444"
	case "HIGH":
		return "#ff8800"
	case "MEDIUM":
		return "#ffcc00"
	case "LOW":
		return "#888888"
	default:
		return "#666666"
	}
}

func verColor(status string) string {
	switch status {
	case "VERIFIED":
		return "#00cc66"
	case "LIKELY":
		return "#3399ff"
	case "POTENTIAL":
		return "#ffcc00"
	default:
		return "#888888"
	}
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}
