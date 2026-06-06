package ruletest

import (
	"math"

	"github.com/RA000WL/syck/internal/rules"
)

type Harness struct{}

func NewHarness() *Harness {
	return &Harness{}
}

type Report struct {
	RuleName       string
	TotalPos       int
	TotalNeg       int
	TruePositives  int
	FalsePositives int
	FalseNegatives int
	Precision      float64
	Recall         float64
	FPRate         float64
	Status         string
}

func (h *Harness) Run(rule rules.Rule, posLines, negLines []string) Report {
	r := Report{RuleName: rule.Name}
	if rule.Compiled() == nil {
		if err := rule.Compile(); err != nil {
			r.Status = StatusSkipped
			return r
		}
	}
	r.TotalPos = len(posLines)
	r.TotalNeg = len(negLines)
	for _, line := range posLines {
		if len(rule.MatchAll(line)) > 0 {
			r.TruePositives++
		} else {
			r.FalseNegatives++
		}
	}
	for _, line := range negLines {
		if len(rule.MatchAll(line)) > 0 {
			r.FalsePositives++
		}
	}
	tpfn := float64(r.TruePositives + r.FalseNegatives)
	tpfp := float64(r.TruePositives + r.FalsePositives)
	if tpfn > 0 {
		r.Recall = float64(r.TruePositives) / tpfn
	}
	if tpfp > 0 {
		r.Precision = float64(r.TruePositives) / tpfp
	}
	if r.TotalNeg > 0 {
		r.FPRate = float64(r.FalsePositives) / float64(r.TotalNeg)
	}
	r.Recall = math.Round(r.Recall*10000) / 10000
	r.Precision = math.Round(r.Precision*10000) / 10000
	r.FPRate = math.Round(r.FPRate*10000) / 10000
	return r
}
