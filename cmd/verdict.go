package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/RA000WL/syck/internal/correlator"
)

var verdictCacheDB string
var verdictStats bool

var verdictCmd = &cobra.Command{
	Use:   "verdict [fingerprint tp|fp ...]",
	Short: "Label findings as true positive or false positive for adaptive learning",
	Long: `Record verdicts on findings to train the adaptive confidence system.

Examples:
  syck verdict abc123 fp --cache-db scan.db
  syck verdict abc123 tp def456 fp --cache-db scan.db
  syck verdict --stats --cache-db scan.db`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verdictCacheDB == "" {
			return fmt.Errorf("--cache-db is required")
		}

		cache, err := correlator.OpenCache(verdictCacheDB)
		if err != nil {
			return fmt.Errorf("open cache: %w", err)
		}
		defer cache.Close()

		if verdictStats {
			return printVerdictStats(cache)
		}

		if len(args) == 0 {
			return fmt.Errorf("provide fingerprint(s) and verdict(s), or use --stats")
		}
		if len(args)%2 != 0 {
			return fmt.Errorf("arguments must be pairs of fingerprint and verdict (tp/fp)")
		}

		for i := 0; i < len(args); i += 2 {
			fp := args[i]
			verdict := args[i+1]
			if verdict != "tp" && verdict != "fp" {
				return fmt.Errorf("invalid verdict %q for %s (must be tp or fp)", verdict, fp)
			}
			if err := cache.Verdict(fp, verdict); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}
			fmt.Printf("Recorded %s verdict for %s\n", verdict, fp)
		}

		if err := cache.RecomputeWeights(); err != nil {
			return fmt.Errorf("recompute weights: %w", err)
		}

		return nil
	},
}

func printVerdictStats(cache *correlator.Cache) error {
	rows, err := cache.GetWeightedStats()
	if err != nil {
		return fmt.Errorf("query stats: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Rule\tFile Pattern\tTP\tFP\tSmoothed\tAdj\tTier")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%.2f\t%+.0f\t%s\n",
			r.RuleName, r.FilePattern, r.TPCount, r.FPCount,
			r.SmoothedFPRatio, r.Modifier, r.TierLabel)
	}
	w.Flush()

	totalVerdicts, _ := cache.TotalVerdicts()
	fmt.Printf("\nTotal verdicts: %d | Adaptive rules: %d\n", totalVerdicts, len(rows))
	return nil
}

func init() {
	verdictCmd.Flags().StringVar(&verdictCacheDB, "cache-db", "", "path to SQLite cache database")
	verdictCmd.Flags().BoolVar(&verdictStats, "stats", false, "show learning summary")
}
