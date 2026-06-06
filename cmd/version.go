package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print syck version",
	Long:  "Print syck version, commit, and build date.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("syck %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  date:   %s\n", Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
