package ruletest

import (
	"fmt"
	"strings"
)

const (
	StatusPassed   = "PASSED"
	StatusRejected = "REJECTED"
	StatusSkipped  = "SKIPPED"
)

func PrintSummary(reports []Report, fpThresholdPct, fnThresholdPct float64) int {
	fmt.Println()
	fmt.Printf("%-40s %4s %4s %4s %4s %4s  %8s  %8s  %8s  %s\n",
		"Rule", "Pos", "Neg", "TP", "FP", "FN", "Precision", "Recall", "FP-rate", "Status")
	fmt.Println(strings.Repeat("-", 100))

	passed := 0
	rejected := 0
	skipped := 0

	for i := range reports {
		updateStatus(&reports[i], fpThresholdPct, fnThresholdPct)
		tp := reports[i].TruePositives
		fp := reports[i].FalsePositives
		fn := reports[i].FalseNegatives

		fmt.Printf("%-40s %4d %4d %4d %4d %4d  %7.2f%%  %7.2f%%  %7.2f%%  %s\n",
			reports[i].RuleName,
			reports[i].TotalPos,
			reports[i].TotalNeg,
			tp, fp, fn,
			reports[i].Precision*100,
			reports[i].Recall*100,
			reports[i].FPRate*100,
			reports[i].Status,
		)
		switch reports[i].Status {
		case StatusPassed:
			passed++
		case StatusRejected:
			rejected++
		case StatusSkipped:
			skipped++
		}
	}

	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("Summary: %d tested, %d %s, %d %s, %d %s\n",
		len(reports), passed, StatusPassed, rejected, StatusRejected, skipped, StatusSkipped)

	return rejected
}

func updateStatus(r *Report, fpThresholdPct, fnThresholdPct float64) {
	if r.Status == StatusSkipped {
		return
	}
	fpThreshold := fpThresholdPct / 100.0
	fnThreshold := fnThresholdPct / 100.0
	recallThreshold := 1.0 - fnThreshold

	if r.FPRate > fpThreshold {
		r.Status = StatusRejected
		return
	}
	if r.TotalPos > 0 && r.Recall < recallThreshold {
		r.Status = StatusRejected
		return
	}
	r.Status = StatusPassed
}
