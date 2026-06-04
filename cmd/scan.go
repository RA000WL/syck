package cmd

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/RA000WL/syck/config"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/formatters"
	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files and directories for secrets",
	Long: `Scan files and directories for API keys, tokens, passwords,
and other secrets.

Examples:
  syck scan .
  syck scan ./src ./config
  syck scan . --severity CRITICAL
  syck scan . --format json -o results.json
  syck scan . --redact --no-color`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd, args)
	},
}

var (
	rulesFile   string
	severityStr string
	formatStr   string
	outputFile  string
	redact      bool
	noDedup     bool
	excludeStr  string
	quiet       bool
	workers     int
	maxFileSize string
)

func init() {
	scanCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "custom rules YAML file")
	scanCmd.Flags().StringVarP(&severityStr, "severity", "s", "LOW", "minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().StringVarP(&formatStr, "format", "f", "text", "output format (text, json)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "write output to file instead of stdout")
	scanCmd.Flags().BoolVar(&redact, "redact", false, "mask secret values in output")
	scanCmd.Flags().BoolVar(&noDedup, "no-dedup", false, "show all occurrences")
	scanCmd.Flags().StringVarP(&excludeStr, "exclude", "e", "", "path exclusion regex")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress banner/warnings")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 10, "concurrent workers")
	scanCmd.Flags().StringVar(&maxFileSize, "max-file-size", "5M", "maximum file size to scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	v, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cfg := config.Default()
	if err := v.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sev := finding.ParseSeverity(severityStr)

	var excludeRegex *regexp.Regexp
	if excludeStr != "" {
		excludeRegex, err = regexp.Compile(excludeStr)
		if err != nil {
			return fmt.Errorf("invalid exclude regex: %w", err)
		}
	}

	ruleset := viper.GetString("rules")
	if rulesFile != "" {
		ruleset = rulesFile
	}

	var rs *rules.RuleSet
	if ruleset != "" {
		rs, err = rules.LoadFile(ruleset)
		if err != nil {
			return fmt.Errorf("load rules: %w", err)
		}
	} else {
		rs, err = rules.LoadDefault()
		if err != nil {
			return fmt.Errorf("load default rules: %w", err)
		}
	}

	maxSize := parseSize(maxFileSize)

	scanCfg := scanner.Config{
		Workers:     workers,
		MaxFileSize: maxSize,
		Exclude:     excludeRegex,
		Rules:       rs,
		MinSeverity: sev,
		NoDedup:     noDedup,
		Debug:       debugMode,
	}

	findings, err := scanner.ScanPaths(args, scanCfg)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	fmtter := formatters.New(formatStr)
	opts := formatters.FormatOptions{
		NoColor: noColor,
		Redact:  redact,
		Quiet:   quiet,
	}

	output, err := fmtter.Format(findings, opts)
	if err != nil {
		return fmt.Errorf("format output: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
	} else {
		fmt.Print(output)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
	return nil
}

func parseSize(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 5 * 1024 * 1024
	}

	s = strings.ToUpper(s)
	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "GB"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 5 * 1024 * 1024
	}
	return n * multiplier
}
