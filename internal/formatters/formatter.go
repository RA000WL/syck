package formatters

import (
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type FormatOptions struct {
	NoColor bool
	Redact  bool
	Quiet   bool
}

type Formatter interface {
	Format(findings []finding.Finding, opts FormatOptions) (string, error)
}

// RedactSecret masks a secret value and replaces it within context strings.
func RedactSecret(secret string) string {
	if len(secret) > 4 {
		return secret[:4] + strings.Repeat("*", len(secret)-4)
	}
	return strings.Repeat("*", len(secret))
}

func New(name string) Formatter {
	switch name {
	case "json":
		return &JSONFormatter{}
	case "sarif":
		return &SARIFFormatter{}
	case "markdown", "md":
		return &MarkdownFormatter{}
	case "csv":
		return &CSVFormatter{}
	case "html":
		return &HTMLFormatter{}
	default:
		return &TextFormatter{}
	}
}
