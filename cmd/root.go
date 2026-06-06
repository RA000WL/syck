package cmd

import (
	"errors"
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
		bindEnvToFlags(cmd.Root())
		return nil
	},
	SilenceErrors: true, // errExitCode is a normal signal (exit 1 due to findings), not an error
	SilenceUsage:  true, // don't dump usage on errExitCode
}

var (
	cfgFile   string
	noColor   bool
	debugMode bool

	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func SetVersionInfo(v, c, d string) {
	Version, Commit, Date = v, c, d
}

func Execute() {
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(listRulesCmd)
	rootCmd.AddCommand(ruletestCmd)
	rootCmd.AddCommand(uploadSarifCmd)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	rootCmd.PersistentFlags().BoolVar(&debugMode, "debug", false, "debug logging")

	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, errExitCode) {
			os.Exit(1)
		}
		os.Exit(1)
	}
}
