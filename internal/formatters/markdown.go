package formatters

import (
	"fmt"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type MarkdownFormatter struct{}

func (f *MarkdownFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	b.WriteString("# Syck Scan Results\n\n")

	if !opts.Quiet {
		b.WriteString("> **WARNING:** secrets are shown IN FULL — do not share this output publicly.\n\n")
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
		b.WriteString(fmt.Sprintf("## `%s`\n\n", file))
		b.WriteString("| Line | Severity | Rule | Entropy | Secret |\n")
		b.WriteString("|------|----------|------|---------|--------|\n")
		for _, f := range ff {
			b.WriteString(fmt.Sprintf("| %d | %s | `%s` | %.3f | `%s` |\n",
				f.Line, finding.SeverityNames[f.Severity], f.RuleName, f.Entropy, f.Secret))
		}
		b.WriteString("\n")
	}

	summary := finding.BuildSummary(findings)
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Files with findings:** %d\n", summary.FilesWithFindings))
	b.WriteString(fmt.Sprintf("- **Total findings:** %d\n\n", summary.TotalFindings))

	if summary.TotalFindings > 0 {
		b.WriteString("| Severity | Count |\n")
		b.WriteString("|----------|-------|\n")
		sevs := make([]finding.Severity, 0, len(summary.BySeverity))
		for s := range summary.BySeverity {
			sevs = append(sevs, s)
		}
		finding.SeverityOrder(sevs)
		for _, s := range sevs {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", finding.SeverityNames[s], summary.BySeverity[s]))
		}
	}

	return b.String(), nil
}
