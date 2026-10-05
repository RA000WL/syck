package formatters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

// twoRuleFinding is one occurrence matched by two rules: RuleName is the
// primary (highest severity) rule and RuleNames lists both.
func twoRuleFinding() finding.Finding {
	return finding.Finding{
		File:           "app.env",
		Line:           3,
		Column:         7,
		RuleName:       "aws_access_key_id",
		RuleNames:      []string{"aws_access_key_id", "dotenv_file_secret"},
		Severity:       finding.SeverityHigh,
		RiskScore:      3,
		Secret:         "AKIAIOSFODNN7EXAMPLE",
		Context:        "KEY=AKIAIOSFODNN7EXAMPLE",
		Entropy:        4.2,
		ConfidenceBand: "HIGH",
	}
}

func singleRuleFinding() finding.Finding {
	return finding.Finding{
		File:           "app.env",
		Line:           3,
		Column:         7,
		RuleName:       "aws_access_key_id",
		RuleNames:      []string{"aws_access_key_id"},
		Severity:       finding.SeverityHigh,
		RiskScore:      3,
		Secret:         "AKIAIOSFODNN7EXAMPLE",
		Context:        "KEY=AKIAIOSFODNN7EXAMPLE",
		Entropy:        4.2,
		ConfidenceBand: "HIGH",
	}
}

func TestJSONIncludesRuleNames(t *testing.T) {
	out, err := (&JSONFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var doc struct {
		Findings []struct {
			Rules []string `json:"rules"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
	}
	if got := doc.Findings[0].Rules; len(got) != 2 || got[1] != "dotenv_file_secret" {
		t.Errorf("rules = %q, want both rule names (sibling dotenv_file_secret missing)", got)
	}

	// single-rule output must stay byte-identical to the pre-RuleNames shape
	single, err := (&JSONFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(single, `"rules"`) {
		t.Errorf("single-rule JSON contains a rules key; it must be omitted\n%s", single)
	}
}

func TestJSONLIncludesRuleNames(t *testing.T) {
	out, err := (&JSONLFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var rec struct {
		Rules []string `json:"rules"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(rec.Rules) != 2 || rec.Rules[1] != "dotenv_file_secret" {
		t.Errorf("rules = %q, want both rule names", rec.Rules)
	}

	single, err := (&JSONLFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(single, `"rules"`) {
		t.Errorf("single-rule JSONL contains a rules key; it must be omitted\n%s", single)
	}
}

func TestCSVIncludesRuleNames(t *testing.T) {
	out, err := (&CSVFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 row, got %d lines:\n%s", len(lines), out)
	}
	header := strings.Split(lines[0], ",")
	ruleCol := -1
	for i, h := range header {
		if h == "rules" {
			ruleCol = i
		}
	}
	if ruleCol < 0 {
		t.Fatalf("CSV header missing rules column: %s", lines[0])
	}
	row := strings.Split(lines[1], ",")
	if len(row) != len(header) {
		t.Fatalf("row has %d fields, header has %d: %s", len(row), len(header), lines[1])
	}
	if !strings.Contains(row[ruleCol], "dotenv_file_secret") {
		t.Errorf("rules column = %q, want sibling dotenv_file_secret", row[ruleCol])
	}

	single, err := (&CSVFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	singleRow := strings.Split(strings.Split(strings.TrimSpace(single), "\n")[1], ",")
	if singleRow[ruleCol] != "" {
		t.Errorf("single-rule rules column = %q, want empty", singleRow[ruleCol])
	}
}

func TestMarkdownIncludesRuleNames(t *testing.T) {
	out, err := (&MarkdownFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(out, "(also: dotenv_file_secret)") {
		t.Errorf("markdown missing sibling rule suffix:\n%s", out)
	}

	single, err := (&MarkdownFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(single, "also:") {
		t.Errorf("single-rule markdown contains a sibling suffix; output changed:\n%s", single)
	}
}

func TestHTMLIncludesRuleNames(t *testing.T) {
	out, err := (&HTMLFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(out, "(also: dotenv_file_secret)") {
		t.Errorf("HTML missing sibling rule suffix:\n%s", out)
	}

	single, err := (&HTMLFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(single, "also:") {
		t.Errorf("single-rule HTML contains a sibling suffix; output changed:\n%s", single)
	}
}

func TestSARIFIncludesRuleNames(t *testing.T) {
	out, err := (&SARIFFormatter{}).Format([]finding.Finding{twoRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							RelatedRules []string `json:"relatedRules"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	rules := doc.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule descriptor, got %d", len(rules))
	}
	rel := rules[0].Properties.RelatedRules
	if len(rel) != 1 || rel[0] != "dotenv_file_secret" {
		t.Errorf("relatedRules = %q, want [dotenv_file_secret]", rel)
	}

	single, err := (&SARIFFormatter{}).Format([]finding.Finding{singleRuleFinding()}, FormatOptions{})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(single, "relatedRules") {
		t.Errorf("single-rule SARIF contains relatedRules; output changed:\n%s", single)
	}
}
