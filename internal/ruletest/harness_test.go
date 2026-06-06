package ruletest

import (
	"testing"

	"github.com/RA000WL/syck/internal/rules"
)

func TestRunZeroPosNeg(t *testing.T) {
	h := NewHarness()
	r := rules.Rule{Name: "test", Pattern: "abc"}
	report := h.Run(r, nil, nil)
	if report.RuleName != "test" {
		t.Errorf("RuleName = %q, want %q", report.RuleName, "test")
	}
}

func TestRunPositiveMatch(t *testing.T) {
	h := NewHarness()
	r := rules.Rule{Name: "test", Pattern: "secret"}
	report := h.Run(r, []string{"this has secret in it"}, nil)
	if report.TruePositives != 1 {
		t.Errorf("TP = %d, want 1", report.TruePositives)
	}
	if report.FalseNegatives != 0 {
		t.Errorf("FN = %d, want 0", report.FalseNegatives)
	}
}

func TestRunFalseNegative(t *testing.T) {
	h := NewHarness()
	r := rules.Rule{Name: "test", Pattern: "secret"}
	report := h.Run(r, []string{"this has nothing"}, nil)
	if report.FalseNegatives != 1 {
		t.Errorf("FN = %d, want 1", report.FalseNegatives)
	}
}

func TestRunFalsePositive(t *testing.T) {
	h := NewHarness()
	r := rules.Rule{Name: "test", Pattern: "secret"}
	report := h.Run(r, nil, []string{"this has secret in it"})
	if report.FalsePositives != 1 {
		t.Errorf("FP = %d, want 1", report.FalsePositives)
	}
}

func TestRunAllUncompiled(t *testing.T) {
	h := NewHarness()
	r := rules.Rule{Name: "test", Pattern: "(invalid"}
	report := h.Run(r, []string{"abc"}, nil)
	if report.Status != StatusSkipped {
		t.Errorf("Status = %q, want SKIPPED for uncompilable regex", report.Status)
	}
}
