package formatters

import (
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type FormatOptions struct {
	NoColor bool
	Redact  bool
	Quiet   bool
	Version string
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

// AttributedRules returns the full rule list for machine-readable output, or
// nil when a single rule matched. DeduplicateBySecret always populates
// RuleNames, so a one-element list carries no information the sibling
// `rule` field does not already carry — omitting it keeps single-rule output
// byte-identical to the pre-RuleNames shape.
func AttributedRules(f finding.Finding) []string {
	if len(f.RuleNames) < 2 {
		return nil
	}
	return f.RuleNames
}

// SiblingRuleNames returns the rules that also matched the same occurrence,
// excluding the primary RuleName. Empty for a single-rule finding so those
// outputs stay byte-identical to the pre-RuleNames shape.
func SiblingRuleNames(f finding.Finding) []string {
	if len(f.RuleNames) < 2 {
		return nil
	}
	siblings := make([]string, 0, len(f.RuleNames)-1)
	for _, name := range f.RuleNames {
		if name != f.RuleName {
			siblings = append(siblings, name)
		}
	}
	if len(siblings) == 0 {
		return nil
	}
	return siblings
}

// RuleCell renders a rule name for a table/report cell: the primary rule plus
// a compact "(also: ...)" suffix when sibling rules matched the same occurrence.
func RuleCell(f finding.Finding) string {
	siblings := SiblingRuleNames(f)
	if len(siblings) == 0 {
		return f.RuleName
	}
	return f.RuleName + " (also: " + strings.Join(siblings, ", ") + ")"
}

func New(name string) Formatter {
	switch name {
	case "json":
		return &JSONFormatter{}
	case "jsonl", "ndjson":
		return &JSONLFormatter{}
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
