package formatters

import (
	"encoding/json"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type jsonlFinding struct {
	File             string  `json:"file"`
	Line             int     `json:"line"`
	Column           int     `json:"column,omitempty"`
	Rule             string  `json:"rule"`
	Severity         string  `json:"severity"`
	RiskScore        int     `json:"risk_score,omitempty"`
	Secret           string  `json:"secret"`
	Entropy          float64 `json:"entropy"`
	Context          string  `json:"context"`
	ContextBefore    string  `json:"context_before,omitempty"`
	ContextAfter     string  `json:"context_after,omitempty"`
	Confidence       string  `json:"confidence,omitempty"`
	Verification     string  `json:"verification_status,omitempty"`
	DecodedPrev      string  `json:"decoded_value_preview,omitempty"`
	AdaptiveModifier int     `json:"adaptive_modifier,omitempty"`
	LearningTier     string  `json:"learning_tier,omitempty"`
}

type JSONLFormatter struct{}

func (f *JSONLFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	if len(findings) == 0 {
		return "", nil
	}

	var sb strings.Builder
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

		jf := jsonlFinding{
			File:             f.File,
			Line:             f.Line,
			Column:           f.Column,
			Rule:             f.RuleName,
			Severity:         finding.SeverityNames[f.Severity],
			RiskScore:        f.RiskScore,
			Secret:           secret,
			Entropy:          f.Entropy,
			Context:          ctx,
			ContextBefore:    ctxBefore,
			ContextAfter:     ctxAfter,
			Confidence:       f.ConfidenceBand,
			Verification:     f.VerificationStatus,
			DecodedPrev:      f.DecodedValuePreview,
			AdaptiveModifier: f.AdaptiveModifier,
			LearningTier:     f.LearningTier,
		}

		data, err := json.Marshal(jf)
		if err != nil {
			return "", err
		}
		sb.Write(data)
		if i < len(findings)-1 {
			sb.WriteByte('\n')
		}
	}

	return sb.String(), nil
}
