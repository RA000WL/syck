package formatters

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type TextFormatter struct{}

var ansi = struct {
	reset   string
	red     string
	yellow  string
	cyan    string
	magenta string
	gray    string
	bold    string
	dim     string
	green   string
	white   string
	blue    string
}{
	reset:   "\033[0m",
	red:     "\033[91m",
	yellow:  "\033[93m",
	cyan:    "\033[96m",
	magenta: "\033[95m",
	gray:    "\033[90m",
	bold:    "\033[1m",
	dim:     "\033[2m",
	green:   "\033[92m",
	white:   "\033[97m",
	blue:    "\033[94m",
}

var sevIcon = map[finding.Severity]string{
	finding.SeverityCritical: "🔴",
	finding.SeverityHigh:     "🟠",
	finding.SeverityMedium:   "🟡",
	finding.SeverityLow:      "🟢",
	finding.SeverityInfo:     "⚪",
}

func (f *TextFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	if !opts.Quiet {
		b.WriteString(f.renderBanner(opts))
	}

	byFile := make(map[string][]finding.Finding)
	for _, finding := range findings {
		cp := finding
		if opts.Redact {
			masked := RedactSecret(finding.Secret)
			cp.Secret = masked
			cp.Context = strings.ReplaceAll(finding.Context, finding.Secret, masked)
			cp.ContextBefore = strings.ReplaceAll(finding.ContextBefore, finding.Secret, masked)
			cp.ContextAfter = strings.ReplaceAll(finding.ContextAfter, finding.Secret, masked)
		}
		byFile[finding.File] = append(byFile[finding.File], cp)
	}

	for _, file := range sortedFiles(byFile) {
		ff := byFile[file]
		b.WriteString(f.renderFileHeader(file, opts))
		for _, finding := range ff {
			b.WriteString(f.renderFinding(finding, opts))
		}
		b.WriteString("\n")
	}

	summary := finding.BuildBasicSummary(findings)
	b.WriteString(f.renderSummary(summary, opts))

	return b.String(), nil
}

func (f *TextFormatter) renderBanner(opts FormatOptions) string {
	if opts.NoColor {
		return "syck v" + opts.Version + " — secret scanner & recon engine\n\n"
	}
	return fmt.Sprintf("%s%s╔════════════════════════════════════════════════════════════╗%s\n"+
		"%s%s║  syck v%-52s║%s\n"+
		"%s%s║  Secret Scanner & Recon Engine                           ║%s\n"+
		"%s%s╚════════════════════════════════════════════════════════════╝%s\n\n"+
		"%s%s⚠  WARNING: Secrets are shown in full. Do not share this output.%s\n\n",
		ansi.bold, ansi.cyan, ansi.reset,
		ansi.bold, ansi.cyan, opts.Version, ansi.reset,
		ansi.bold, ansi.cyan, ansi.reset,
		ansi.bold, ansi.cyan, ansi.reset,
		ansi.yellow, ansi.dim, ansi.reset)
}

func (f *TextFormatter) renderFileHeader(file string, opts FormatOptions) string {
	if opts.NoColor {
		return fmt.Sprintf("┌─ %s\n", file)
	}
	return fmt.Sprintf("%s%s┌─ %s%s\n", ansi.bold, ansi.magenta, file, ansi.reset)
}

func (f *TextFormatter) renderFinding(find finding.Finding, opts FormatOptions) string {
	var b strings.Builder

	icon := sevIcon[find.Severity]
	sevColor := severityColor(find.Severity, opts.NoColor)
	sevName := finding.SeverityNames[find.Severity]

	rule := find.RuleName
	riskMarker := ""
	if find.RiskScore >= 8 {
		riskMarker = " [!+]"
	} else if find.RiskScore >= 5 {
		riskMarker = " [!]"
	}
	if len(rule) > 30 {
		rule = rule[:27] + "..."
	}

	loc := fmt.Sprintf("%d:%d", find.Line, find.Column)

	if opts.NoColor {
		b.WriteString(fmt.Sprintf("│ %s %-8s │ %s │ %-30s%s │ %s\n", icon, sevName, loc, rule, riskMarker, truncateStr(find.Secret, 50)))
		if find.Context != "" {
			b.WriteString(fmt.Sprintf("│   %s\n", truncateStr(find.Context, 70)))
		}
	} else {
		b.WriteString(fmt.Sprintf("│ %s %-8s%s │ %s%-8s%s │ %s%-30s%s%s │ %s%s%s\n",
			icon, sevName, ansi.reset,
			sevColor, sevName, ansi.reset,
			ansi.cyan, rule, riskMarker, ansi.reset,
			ansi.white, truncateStr(find.Secret, 50), ansi.reset))
		if find.Context != "" {
			b.WriteString(fmt.Sprintf("│   %s%s%s\n", ansi.dim, truncateStr(find.Context, 70), ansi.reset))
		}
	}

	return b.String()
}

func (f *TextFormatter) renderSummary(summary finding.Summary, opts FormatOptions) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n%s─── Scan Complete ────────────────────────────────────────────%s\n\n", ansi.bold, ansi.reset))
	b.WriteString(fmt.Sprintf("  Files scanned    : %d\n", summary.FilesWithFindings))
	b.WriteString(fmt.Sprintf("  Total findings   : %d\n\n", summary.TotalFindings))

	if summary.TotalFindings > 0 && !opts.NoColor {
		maxCount := 0
		for _, count := range summary.BySeverity {
			if count > maxCount {
				maxCount = count
			}
		}

		sevs := make([]finding.Severity, 0, len(summary.BySeverity))
		for s := range summary.BySeverity {
			sevs = append(sevs, s)
		}
		finding.SeverityOrder(sevs)

		b.WriteString("  Severity Distribution:\n\n")
		for _, s := range sevs {
			count := summary.BySeverity[s]
			barLen := 0
			if maxCount > 0 {
				barLen = (count * 30) / maxCount
			}
			if barLen < 1 && count > 0 {
				barLen = 1
			}

			sevColor := severityColor(s, opts.NoColor)
			bar := strings.Repeat("█", barLen)
			empty := strings.Repeat("░", 30-barLen)

			b.WriteString(fmt.Sprintf("    %s%-10s%s %s%s%s%s %d\n",
				sevColor, finding.SeverityNames[s], ansi.reset,
				ansi.bold, bar, ansi.reset,
				empty, count))
		}
	} else if summary.TotalFindings > 0 {
		sevs := make([]finding.Severity, 0, len(summary.BySeverity))
		for s := range summary.BySeverity {
			sevs = append(sevs, s)
		}
		finding.SeverityOrder(sevs)
		for _, s := range sevs {
			b.WriteString(fmt.Sprintf("    %-10s %d\n", finding.SeverityNames[s], summary.BySeverity[s]))
		}
	} else {
		b.WriteString(fmt.Sprintf("  %s✓ No secrets found%s\n", ansi.green, ansi.reset))
	}

	return b.String()
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func severityColor(s finding.Severity, noColor bool) string {
	if noColor {
		return ""
	}
	switch s {
	case finding.SeverityCritical:
		return ansi.red + ansi.bold
	case finding.SeverityHigh:
		return ansi.yellow + ansi.bold
	case finding.SeverityMedium:
		return ansi.yellow
	case finding.SeverityLow:
		return ansi.green
	default:
		return ansi.gray
	}
}

func confidenceColor(confidence string, noColor bool) string {
	if noColor || confidence == "" {
		return ""
	}
	switch confidence {
	case "CRITICAL", "VERY_HIGH":
		return ansi.red + ansi.bold
	case "HIGH":
		return ansi.bold
	case "MEDIUM":
		return ""
	case "LOW":
		return ansi.dim
	default:
		return ""
	}
}

func sortedFiles(m map[string][]finding.Finding) []string {
	var files []string
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}
