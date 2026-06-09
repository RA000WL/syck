package formatters

import (
	"fmt"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type CSVFormatter struct{}

func csvEscape(field string) string {
	if strings.ContainsAny(field, ",\"\n\r") {
		field = strings.ReplaceAll(field, `"`, `""`)
		return `"` + field + `"`
	}
	return field
}

func (f *CSVFormatter) Format(findings []finding.Finding, opts FormatOptions) (string, error) {
	var b strings.Builder

	b.WriteString("file,line,column,rule,severity,risk_score,secret,entropy,context,confidence,verification_status,decoded_value_preview\n")

	for _, f := range findings {
		secret := f.Secret
		ctx := f.Context
		if opts.Redact {
			masked := RedactSecret(f.Secret)
			secret = masked
			ctx = strings.ReplaceAll(f.Context, f.Secret, masked)
		}

		b.WriteString(fmt.Sprintf("%s,%d,%d,%s,%s,%d,%s,%.3f,%s,%s,%s,%s\n",
			csvEscape(f.File),
			f.Line,
			f.Column,
			csvEscape(f.RuleName),
			finding.SeverityNames[f.Severity],
			f.RiskScore,
			csvEscape(secret),
			f.Entropy,
			csvEscape(ctx),
			csvEscape(f.ConfidenceBand),
			csvEscape(f.VerificationStatus),
			csvEscape(f.DecodedValuePreview),
		))
	}

	return b.String(), nil
}
