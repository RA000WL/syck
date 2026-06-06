package cmd

import (
	"fmt"

	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/ruletest"
	"github.com/spf13/cobra"
)

var (
	ruleFilter     string
	fpThresholdPct float64
	fnThresholdPct float64
)

var ruletestCmd = &cobra.Command{
	Use:   "ruletest",
	Short: "Run quality tests on built-in rules",
	Long: `Load all built-in rules, test each against a positive corpus
(tokens the rule should match) and a negative corpus (tokens it should NOT match).
Reports precision, recall, and false-positive rate per rule.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rs, err := rules.LoadDefault()
		if err != nil {
			return fmt.Errorf("loading rules: %w", err)
		}

		h := ruletest.NewHarness()
		negLines := ruletest.LoadNegative()
		if negLines == nil {
			fmt.Println("WARNING: negative corpus is empty — FP rate will be 0 for all rules")
		}

		var allReports []ruletest.Report
		for _, rule := range rs.Rules {
			if ruleFilter != "" && rule.Name != ruleFilter {
				continue
			}
			posLines := ruletest.LoadPositive(rule.Name)
			if posLines == nil {
				continue
			}
			allReports = append(allReports, h.Run(rule, posLines, negLines))
		}

		rejected := ruletest.PrintSummary(allReports, fpThresholdPct, fnThresholdPct)
		if rejected > 0 {
			return fmt.Errorf("%d rule(s) REJECTED", rejected)
		}
		return nil
	},
}

func init() {
	ruletestCmd.Flags().StringVar(&ruleFilter, "rule", "", "test only this rule")
	ruletestCmd.Flags().Float64Var(&fpThresholdPct, "fp-threshold", 0.5, "max FP rate % before REJECTED")
	ruletestCmd.Flags().Float64Var(&fnThresholdPct, "fn-threshold", 5.0, "max FN rate % before REJECTED")
}
