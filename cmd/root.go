package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "syck",
	Short: "Secret scanner for bug bounty hunting",
	Long: `Syck is a modular secret scanner with 250+ detection rules,
entropy analysis, and multiple output formats.

Scan files and directories for API keys, tokens, passwords, 
and other secrets before they end up in the wrong hands.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var (
	cfgFile   string
	noColor   bool
	debugMode bool
)

func Execute() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(listRulesCmd)
	rootCmd.AddCommand(ruletestCmd)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "debug logging")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
