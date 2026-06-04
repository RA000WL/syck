package formatters

import (
	"encoding/json"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type JSONFormatter struct{}

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
	Summary  jsonSummary   `json:"summary"`
}

type jsonFinding struct {
	File     string  `json:"file"`
	Line     int     `json:"line"`
	Column   int     `json:"column"`
	Rule     string  `json:"rule"`
	Severity string  `json:"severity"`
	Secret   string  `json:"secret"`
	Context  string  `json:"context"`
	Entropy  float64 `json:"entropy"`
}

type jsonSummary struct {
	FilesWithFindings int              `json:"files_with_findings"`
	TotalFindings     int              `json:"total_findings"`
	BySeverity        map[string]int   `json:"by_severity"`
}

func (f *JSONFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	out := jsonOutput{
		Findings: make([]jsonFinding, len(findings)),
	}

	for i, f := range findings {
		secret := f.Secret
		if opts.Redact {
			if len(secret) > 4 {
				secret = secret[:4] + strings.Repeat("*", len(secret)-4)
			} else {
				secret = strings.Repeat("*", len(secret))
			}
		}

		out.Findings[i] = jsonFinding{
			File:     f.File,
			Line:     f.Line,
			Column:   f.Column,
			Rule:     f.RuleName,
			Severity: finding.SeverityNames[f.Severity],
			Secret:   secret,
			Context:  f.Context,
			Entropy:  f.Entropy,
		}
	}

	summary := finding.BuildSummary(findings)
	out.Summary = jsonSummary{
		FilesWithFindings: summary.FilesWithFindings,
		TotalFindings:     summary.TotalFindings,
		BySeverity:        make(map[string]int),
	}

	for s, count := range summary.BySeverity {
		out.Summary.BySeverity[finding.SeverityNames[s]] = count
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
