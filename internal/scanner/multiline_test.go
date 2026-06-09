package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/rules"
)

func TestMultiLineScanner_Basic(t *testing.T) {
	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{Name: "pem_key", Severity: "HIGH", Pattern: "-----BEGIN[\\s\\S]*?-----END", MultiLine: true},
		},
	}
	if err := rs.CompileAll(); err != nil {
		t.Fatal(err)
	}
	mls := NewMultiLineScanner(rs, 0)
	lines := []string{"before", "-----BEGIN CERTIFICATE-----", "abcdefghijklmnop", "-----END CERTIFICATE-----", "after"}
	findings := mls.ScanMultiLine(lines, "test.txt", 2)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestMultiLineScanner_NoMultiLine(t *testing.T) {
	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{Name: "single", Severity: "HIGH", Pattern: "test"},
		},
	}
	if err := rs.CompileAll(); err != nil {
		t.Fatal(err)
	}
	mls := NewMultiLineScanner(rs, 0)
	findings := mls.ScanMultiLine([]string{"line1", "line2"}, "test.txt", 1)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
