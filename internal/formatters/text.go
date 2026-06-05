package formatters

import (
	"fmt"
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
}{
	reset:   "\033[0m",
	red:     "\033[91m",
	yellow:  "\033[93m",
	cyan:    "\033[96m",
	magenta: "\033[95m",
	gray:    "\033[90m",
	bold:    "\033[1m",
}

func (f *TextFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	if !opts.Quiet {
		if !opts.NoColor {
			b.WriteString(fmt.Sprintf("%s%s  WARNING: secrets are shown IN FULL — do not share this output publicly.%s\n\n",
				ansi.yellow, ansi.bold, ansi.reset))
		} else {
			b.WriteString("WARNING: secrets are shown IN FULL — do not share this output publicly.\n\n")
		}
	}

	byFile := make(map[string][]finding.Finding)
	for _, f := range findings {
		cp := f
		if opts.Redact {
			masked := RedactSecret(f.Secret)
			cp.Secret = masked
			cp.Context = strings.ReplaceAll(f.Context, f.Secret, masked)
			cp.ContextBefore = strings.ReplaceAll(f.ContextBefore, f.Secret, masked)
			cp.ContextAfter = strings.ReplaceAll(f.ContextAfter, f.Secret, masked)
		}
		byFile[f.File] = append(byFile[f.File], cp)
	}

	for _, file := range sortedFiles(byFile) {
		ff := byFile[file]

		if !opts.NoColor {
			b.WriteString(fmt.Sprintf("%s%s%s\n", ansi.bold, ansi.magenta, file))
			b.WriteString(fmt.Sprintf("%s%s\n", ansi.reset, ansi.reset))
		} else {
			b.WriteString(fmt.Sprintf("%s\n", file))
		}

		for _, f := range ff {
			sevColor := severityColor(f.Severity, opts.NoColor)
			sevName := finding.SeverityNames[f.Severity]

			line := f.Line
			col := f.Column
			rule := f.RuleName

			if !opts.NoColor {
				b.WriteString(fmt.Sprintf("  %s%d%s:%s%d%s  %s[%s]%s %s[%s]%s  entropy=%s%.3f%s\n",
					ansi.gray, line, ansi.reset,
					ansi.gray, col, ansi.reset,
					sevColor, sevName, ansi.reset,
					ansi.cyan, rule, ansi.reset,
					ansi.gray, f.Entropy, ansi.reset))
				b.WriteString(fmt.Sprintf("       secret : %s%s%s\n", ansi.yellow, f.Secret, ansi.reset))
				b.WriteString(fmt.Sprintf("       context: %s%s%s\n", ansi.gray, f.Context, ansi.reset))
			} else {
				b.WriteString(fmt.Sprintf("  %d:%d  [%s] [%s]  entropy=%.3f\n", line, col, sevName, rule, f.Entropy))
				b.WriteString(fmt.Sprintf("       secret : %s\n", f.Secret))
				b.WriteString(fmt.Sprintf("       context: %s\n", f.Context))
			}
		}
	}

	summary := finding.BuildSummary(findings)
	b.WriteString("\n── Summary ──────────────────────────────\n")
	b.WriteString(fmt.Sprintf("  Files with findings : %d\n", summary.FilesWithFindings))
	b.WriteString(fmt.Sprintf("  Total findings      : %d\n", summary.TotalFindings))

	if summary.TotalFindings > 0 {
		sevs := make([]finding.Severity, 0, len(summary.BySeverity))
		for s := range summary.BySeverity {
			sevs = append(sevs, s)
		}
		finding.SeverityOrder(sevs)
		for _, s := range sevs {
			sevColor := severityColor(s, opts.NoColor)
			if !opts.NoColor {
				b.WriteString(fmt.Sprintf("    %s%-10s%s %d\n", sevColor, finding.SeverityNames[s], ansi.reset, summary.BySeverity[s]))
			} else {
				b.WriteString(fmt.Sprintf("    %-10s %d\n", finding.SeverityNames[s], summary.BySeverity[s]))
			}
		}
	}

	return b.String(), nil
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
		return ""
	case finding.SeverityLow:
		return ""
	default:
		return ""
	}
}

func sortedFiles(m map[string][]finding.Finding) []string {
	var files []string
	for f := range m {
		files = append(files, f)
	}
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i] > files[j] {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	return files
}
