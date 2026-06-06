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
	File          string  `json:"file"`
	Line          int     `json:"line"`
	Column        int     `json:"column"`
	Rule          string  `json:"rule"`
	Severity      string  `json:"severity"`
	RiskScore     int     `json:"risk_score,omitempty"`
	Secret        string  `json:"secret"`
	Context       string  `json:"context"`
	ContextBefore string  `json:"context_before,omitempty"`
	ContextAfter  string  `json:"context_after,omitempty"`
	Entropy       float64 `json:"entropy"`
	Confidence    string  `json:"confidence,omitempty"`
	Verification  string  `json:"verification_status,omitempty"`
	DecodedPrev   string  `json:"decoded_value_preview,omitempty"`
}

type jsonSummary struct {
	FilesWithFindings int            `json:"files_with_findings"`
	TotalFindings     int            `json:"total_findings"`
	BySeverity        map[string]int `json:"by_severity"`
}

func (f *JSONFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	out := jsonOutput{
		Findings: make([]jsonFinding, len(findings)),
	}

	for i, f := range findings {
		secret := f.Secret
		ctx := f.Context
		ctxBefore := f.ContextBefore
		ctxAfter := f.ContextAfter
		if opts.Redact {
			masked := RedactSecret(f.Secret)
			secret = masked
			ctx = strings.ReplaceAll(f.Context, f.Secret, masked)
			ctxBefore = strings.ReplaceAll(f.ContextBefore, f.Secret, masked)
			ctxAfter = strings.ReplaceAll(f.ContextAfter, f.Secret, masked)
		}

		out.Findings[i] = jsonFinding{
			File:          f.File,
			Line:          f.Line,
			Column:        f.Column,
			Rule:          f.RuleName,
			Severity:      finding.SeverityNames[f.Severity],
			RiskScore:     f.RiskScore,
			Secret:        secret,
			Context:       ctx,
			ContextBefore: ctxBefore,
			ContextAfter:  ctxAfter,
			Entropy:       f.Entropy,
			Confidence:    f.Confidence,
			Verification:  f.VerificationStatus,
			DecodedPrev:   f.DecodedValuePreview,
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
