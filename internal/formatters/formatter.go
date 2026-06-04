package formatters

import "github.com/RA000WL/syck/internal/finding"

type FormatOptions struct {
	NoColor bool
	Redact  bool
	Quiet   bool
}

type Formatter interface {
	Format(findings []finding.Finding, opts FormatOptions) (string, error)
}

func New(name string) Formatter {
	switch name {
	case "json":
		return &JSONFormatter{}
	case "sarif":
		return &SARIFFormatter{}
	default:
		return &TextFormatter{}
	}
}
