package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/RA000WL/syck/internal/rules"
)

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all detection rules and exit",
	RunE: func(cmd *cobra.Command, args []string) error {
		rs, err := rules.LoadDefault()
		if err != nil {
			return fmt.Errorf("load rules: %w", err)
		}

		sevOrder := map[string]int{
			"CRITICAL": 0,
			"HIGH":     1,
			"MEDIUM":   2,
			"LOW":      3,
			"INFO":     4,
		}

		sorted := make([]rules.Rule, len(rs.Rules))
		copy(sorted, rs.Rules)
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				si := sevOrder[sorted[i].Severity]
				sj := sevOrder[sorted[j].Severity]
				if si > sj || (si == sj && sorted[i].Name > sorted[j].Name) {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}

		var b strings.Builder
		b.WriteString(fmt.Sprintf("Built-in Rules (%d total):\n\n", len(sorted)))

		currentSev := ""
		for _, r := range sorted {
			if r.Severity != currentSev {
				currentSev = r.Severity
				b.WriteString(fmt.Sprintf("  %s:\n", currentSev))
			}
			tags := strings.Join(r.Tags, ", ")
			b.WriteString(fmt.Sprintf("    %-45s [%s]\n", r.Name, tags))
		}

		fmt.Print(b.String())
		return nil
	},
}
