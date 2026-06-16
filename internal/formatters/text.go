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

var categoryLabels = map[string]string{
	"secrets":          "Secrets & Credentials",
	"juicy_files":      "Juicy Files Found",
	"endpoints":        "Endpoints Discovered",
	"security_headers": "Security Headers",
	"internal_urls":    "Internal URLs",
	"other":            "Other Findings",
}

func (f *TextFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	if !opts.Quiet {
		b.WriteString(f.renderBanner(opts))
	}

	// Apply redaction if enabled
	processedFindings := make([]finding.Finding, len(findings))
	copy(processedFindings, findings)
	if opts.Redact {
		for i := range processedFindings {
			masked := RedactSecret(processedFindings[i].Secret)
			processedFindings[i].Secret = masked
			processedFindings[i].Context = strings.ReplaceAll(findings[i].Context, findings[i].Secret, masked)
			processedFindings[i].ContextBefore = strings.ReplaceAll(findings[i].ContextBefore, findings[i].Secret, masked)
			processedFindings[i].ContextAfter = strings.ReplaceAll(findings[i].ContextAfter, findings[i].Secret, masked)
		}
	}

	deduped := deduplicateFindings(processedFindings)
	byCategory := groupByCategory(deduped)

	b.WriteString(f.renderQuickSummary(deduped, opts))

	categories := []string{"secrets", "juicy_files", "endpoints", "security_headers", "internal_urls", "other"}
	for _, cat := range categories {
		catFindings := byCategory[cat]
		if len(catFindings) == 0 {
			continue
		}
		b.WriteString(f.renderCategory(cat, catFindings, opts))
	}

	summary := finding.BuildBasicSummary(deduped)
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

func (f *TextFormatter) renderQuickSummary(findings []finding.Finding, opts FormatOptions) string {
	var b strings.Builder
	byCategory := groupByCategory(findings)

	if opts.NoColor {
		b.WriteString("── Quick Summary ──────────────────────────────────────────\n")
		for _, cat := range []string{"secrets", "juicy_files", "endpoints", "security_headers", "internal_urls", "other"} {
			if count := len(byCategory[cat]); count > 0 {
				b.WriteString(fmt.Sprintf("  %-20s %d\n", categoryLabels[cat]+":", count))
			}
		}
		b.WriteString("────────────────────────────────────────────────────────────\n\n")
	} else {
		b.WriteString(fmt.Sprintf("%s%s── Quick Summary ──────────────────────────────────────────%s\n", ansi.bold, ansi.cyan, ansi.reset))
		for _, cat := range []string{"secrets", "juicy_files", "endpoints", "security_headers", "internal_urls", "other"} {
			if count := len(byCategory[cat]); count > 0 {
				b.WriteString(fmt.Sprintf("  %s%-20s%s %s%d%s\n", ansi.bold, categoryLabels[cat]+":", ansi.reset, ansi.green, count, ansi.reset))
			}
		}
		b.WriteString(fmt.Sprintf("%s%s────────────────────────────────────────────────────────────%s\n\n", ansi.bold, ansi.cyan, ansi.reset))
	}

	return b.String()
}

func (f *TextFormatter) renderCategory(category string, findings []finding.Finding, opts FormatOptions) string {
	var b strings.Builder
	label := categoryLabels[category]

	if opts.NoColor {
		b.WriteString(fmt.Sprintf("── %s (%d) ─────────────────────────────────────────────\n", label, len(findings)))
	} else {
		b.WriteString(fmt.Sprintf("%s%s── %s (%d) ─────────────────────────────────────────────%s\n", ansi.bold, ansi.magenta, label, len(findings), ansi.reset))
	}

	if category == "juicy_files" {
		for _, f := range findings {
			path := f.Secret
			if idx := strings.Index(path, " ["); idx > 0 {
				path = path[:idx]
			}
			if opts.NoColor {
				b.WriteString(fmt.Sprintf("  %s\n", path))
			} else {
				b.WriteString(fmt.Sprintf("  %s%s%s\n", ansi.white, path, ansi.reset))
			}
		}
		b.WriteString("\n")
		return b.String()
	}

	for _, f := range findings {
		icon := sevIcon[f.Severity]
		sevName := finding.SeverityNames[f.Severity]
		sevColor := severityColor(f.Severity, opts.NoColor)

		riskMarker := ""
		if f.RiskScore >= 8 {
			riskMarker = " [!+]"
		} else if f.RiskScore >= 5 {
			riskMarker = " [!]"
		}

		if opts.NoColor {
			b.WriteString(fmt.Sprintf("  %s %-8s %s%s\n", icon, sevName, truncateStr(f.Secret, 60), riskMarker))
			if f.Context != "" && f.Context != truncateStr(f.Secret, 60) {
				b.WriteString(fmt.Sprintf("    %s\n", truncateStr(f.Context, 70)))
			}
		} else {
			b.WriteString(fmt.Sprintf("  %s %s%-8s%s %s%s%s%s\n", icon, sevColor, sevName, ansi.reset, ansi.white, truncateStr(f.Secret, 60), riskMarker, ansi.reset))
			if f.Context != "" && f.Context != truncateStr(f.Secret, 60) {
				b.WriteString(fmt.Sprintf("    %s%s%s\n", ansi.dim, truncateStr(f.Context, 70), ansi.reset))
			}
		}
	}
	b.WriteString("\n")

	return b.String()
}

func (f *TextFormatter) renderSummary(summary finding.Summary, opts FormatOptions) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n%s─── Scan Complete ────────────────────────────────────────────%s\n\n", ansi.bold, ansi.reset))
	b.WriteString(fmt.Sprintf("  Total findings   : %d\n", summary.TotalFindings))

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
	}

	return b.String()
}

func deduplicateFindings(findings []finding.Finding) []finding.Finding {
	seen := make(map[string]bool)
	var result []finding.Finding
	for _, f := range findings {
		key := f.File + "|" + f.Secret
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}

func groupByCategory(findings []finding.Finding) map[string][]finding.Finding {
	result := make(map[string][]finding.Finding)
	for _, f := range findings {
		cat := categorizeFinding(f)
		result[cat] = append(result[cat], f)
	}
	return result
}

func categorizeFinding(f finding.Finding) string {
	rule := f.RuleName

	switch {
	case strings.Contains(rule, "secret") || strings.Contains(rule, "api_key") ||
		strings.Contains(rule, "token") || strings.Contains(rule, "password") ||
		strings.Contains(rule, "credential") || strings.Contains(rule, "aws_access") ||
		strings.Contains(rule, "github_token") || strings.Contains(rule, "stripe"):
		return "secrets"
	case strings.Contains(rule, "juicy_file") || strings.Contains(rule, "source_map"):
		return "juicy_files"
	case strings.Contains(rule, "endpoint") || strings.Contains(rule, "openapi") ||
		strings.Contains(rule, "graphql"):
		return "endpoints"
	case strings.Contains(rule, "security-header") || strings.Contains(rule, "attack_surface"):
		return "security_headers"
	case strings.Contains(rule, "internal") || strings.Contains(rule, "private_ip") ||
		strings.Contains(rule, "cloud_metadata") || strings.Contains(rule, "localhost"):
		return "internal_urls"
	default:
		return "other"
	}
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

func sortedFiles(m map[string][]finding.Finding) []string {
	var files []string
	for f := range m {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}
