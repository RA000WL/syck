package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestPipelineSmoke(t *testing.T) {
	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs, _ := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	p := NewPipeline(Config{Rules: rs, MinSeverity: finding.ParseSeverity("LOW")})
	got, err := p.ScanString("hello TOKEN_ABCDEF12 world", "x.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Confidence != "MEDIUM" {
		t.Errorf("Confidence = %q, want MEDIUM (one signal: regex match = 40 pts, no entropy/verification/context)", got[0].Confidence)
	}
}
