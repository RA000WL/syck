package ruletest

import "testing"

func TestUpdateStatusRejectedFP(t *testing.T) {
	r := Report{RuleName: "x", FPRate: 0.02, Recall: 1.0}
	updateStatus(&r, 0.5, 5.0)
	if r.Status != StatusRejected {
		t.Errorf("FP rate 2%% > 0.5%% threshold should REJECT")
	}
}

func TestUpdateStatusRejectedFN(t *testing.T) {
	r := Report{RuleName: "x", FPRate: 0, Recall: 0.90, TotalPos: 10}
	updateStatus(&r, 0.5, 5.0)
	if r.Status != StatusRejected {
		t.Errorf("Recall 90%% < 95%% threshold should REJECT")
	}
}

func TestUpdateStatusPassed(t *testing.T) {
	r := Report{RuleName: "x", FPRate: 0.001, Recall: 0.99, TotalPos: 10}
	updateStatus(&r, 0.5, 5.0)
	if r.Status != StatusPassed {
		t.Errorf("good metrics should PASS")
	}
}

func TestUpdateStatusSkipped(t *testing.T) {
	r := Report{RuleName: "x", Status: StatusSkipped}
	updateStatus(&r, 0.5, 5.0)
	if r.Status != StatusSkipped {
		t.Errorf("SKIPPED should stay SKIPPED")
	}
}

func TestUpdateStatusNoPosLines(t *testing.T) {
	r := Report{RuleName: "x", FPRate: 0, TotalPos: 0}
	updateStatus(&r, 0.5, 5.0)
	if r.Status != StatusPassed {
		t.Errorf("rule with no positive lines should PASS (no FN to measure)")
	}
}
