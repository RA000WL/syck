package cmd

import (
	"bufio"
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
	"github.com/RA000WL/syck/internal/gitscan"
	"github.com/RA000WL/syck/internal/ignore"
	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/scanner"
	"github.com/RA000WL/syck/internal/validator"
)

var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files, directories, or URLs for secrets",
	Long: `Scan files, directories, or URLs for API keys, tokens, passwords,
and other secrets.

Examples:
  syck scan .
  syck scan ./src ./config
  syck scan . --severity CRITICAL
  syck scan . --format json -o results.json
  syck scan . --redact --no-color
  syck scan -u https://example.com/app.js
  syck scan -l urls.txt --scope "example\\.com" --crawl-limit 50`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd, args)
	},
}

var (
	rulesFile       string
	severityStr     string
	formatStr       string
	outputFile      string
	redact          bool
	noDedup         bool
	excludeStr      string
	quiet           bool
	workers         int
	maxFileSize     string
	decodeBase64    bool
	decodeHex       bool
	decodeUnicode   bool
	decodeURL       bool
	decodeGzip      bool
	jsReconstruct   bool
	endpoints       bool
	pipe            bool
	failOn          string
	downgradeFP     bool
	urlList         []string
	urlFile         string
	scopeStr        string
	crawlLimit      int
	crawlDepth      int
	headless        bool
	rateLimit       int
	userAgent       string
	cookies         bool
	cookieFile      string
	concurrency     int
	hostConcurrency int
	ignoreRobots    bool
	gitHistory      bool
	validate        bool
	verify          bool
	verifyRate      int
	ignoreFile      string
	maxScanLineLen  int
)

func init() {
	scanCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "custom rules YAML file")
	scanCmd.Flags().StringVarP(&severityStr, "severity", "s", "LOW", "minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().StringVarP(&formatStr, "format", "f", "text", "output format (text, json, sarif, markdown, csv, html)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "write output to file instead of stdout")
	scanCmd.Flags().BoolVar(&redact, "redact", false, "mask secret values in output")
	scanCmd.Flags().BoolVar(&noDedup, "no-dedup", false, "show all occurrences")
	scanCmd.Flags().StringVarP(&excludeStr, "exclude", "e", "", "path exclusion regex")
	scanCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress banner/warnings")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 10, "concurrent workers")
	scanCmd.Flags().StringVar(&maxFileSize, "max-file-size", "5M", "maximum file size to scan")

	scanCmd.Flags().BoolVar(&decodeBase64, "decode-base64", false, "base64 decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeHex, "decode-hex", false, "hex decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeUnicode, "decode-unicode", false, "decode \\uXXXX escapes and rescan")
	scanCmd.Flags().BoolVar(&decodeURL, "decode-url", false, "URL-decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeGzip, "decode-gzip", false, "decompress gzip/zlib content and rescan")
	scanCmd.Flags().BoolVar(&jsReconstruct, "js-reconstruct", false, "reconstruct JS concatenated strings")
	scanCmd.Flags().BoolVar(&endpoints, "endpoints", false, "extract API/graphql/websocket URLs")
	scanCmd.Flags().BoolVar(&pipe, "pipe", false, "scan from stdin")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "CI gate: exit 1 if findings at or above this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	scanCmd.Flags().BoolVar(&downgradeFP, "downgrade-fp", false, "downgrade severity for findings in test/mock/vendor dirs and placeholder patterns")

	scanCmd.Flags().StringArrayVarP(&urlList, "url", "u", nil, "URL to scan (can be repeated)")
	scanCmd.Flags().StringVarP(&urlFile, "url-file", "l", "", "file containing URLs to scan (one per line)")
	scanCmd.Flags().StringVar(&scopeStr, "scope", "", "regex to filter crawled URLs by domain/path")
	scanCmd.Flags().IntVar(&crawlLimit, "crawl-limit", 100, "max URLs to crawl")
	scanCmd.Flags().IntVar(&crawlDepth, "crawl-depth", 3, "max link follow depth")
	scanCmd.Flags().BoolVar(&headless, "headless", false, "use headless Chrome for JS-rendered pages (SPA)")
	scanCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "max requests per second per host (0=unlimited)")
	scanCmd.Flags().StringVar(&userAgent, "user-agent", "", "custom User-Agent string (empty = random rotation)")
	scanCmd.Flags().BoolVar(&cookies, "cookies", true, "enable cookie jar for session handling")
	scanCmd.Flags().StringVar(&cookieFile, "cookie-file", "", "persist cookies to file between runs")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 10, "max concurrent fetches")
	scanCmd.Flags().IntVar(&hostConcurrency, "host-concurrency", 2, "max concurrent fetches per host")
	scanCmd.Flags().BoolVar(&ignoreRobots, "ignore-robots", false, "ignore robots.txt Disallow rules")
	scanCmd.Flags().BoolVar(&gitHistory, "git-history", false, "scan files in git commit history")
	scanCmd.Flags().BoolVar(&validate, "validate", false, "validate found secrets against provider APIs (live check)")
	scanCmd.Flags().BoolVar(&verify, "verify", false, "verify secrets against provider APIs (V1 state path)")
	scanCmd.Flags().IntVar(&verifyRate, "verify-rate", 5, "max verification requests per second per host")
	scanCmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "path to .syckignore file for fingerprint-based suppression")
	scanCmd.Flags().IntVar(&maxScanLineLen, "max-scan-line-len", 100000, "skip per-line scanning on lines exceeding this length (0=unlimited)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Collect URLs from -u flags and -l file
	var allURLs []string
	allURLs = append(allURLs, urlList...)

	if urlFile != "" {
		f, err := os.Open(urlFile)
		if err != nil {
			return fmt.Errorf("open url file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				allURLs = append(allURLs, line)
			}
		}
	}

	urlMode := len(allURLs) > 0

	if !pipe && !urlMode && len(args) == 0 {
		return fmt.Errorf("requires at least 1 path argument, --url, --url-file, or use --pipe for stdin")
	}

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

	var scopeRegex *regexp.Regexp
	if scopeStr != "" {
		scopeRegex, err = regexp.Compile(scopeStr)
		if err != nil {
			return fmt.Errorf("invalid scope regex: %w", err)
		}
	}

	scanCfg := scanner.Config{
		Workers:         workers,
		MaxFileSize:     maxSize,
		Exclude:         excludeRegex,
		Rules:           rs,
		MinSeverity:     sev,
		NoDedup:         noDedup,
		Debug:           debugMode,
		DecodeBase64:    decodeBase64,
		DecodeHex:       decodeHex,
		DecodeUnicode:   decodeUnicode,
		DecodeURL:       decodeURL,
		DecodeGzip:      decodeGzip,
		JSReconstruct:   jsReconstruct,
		Endpoints:       endpoints,
		DowngradeFP:     downgradeFP,
		URLs:            allURLs,
		URLFile:         urlFile,
		Scope:           scopeRegex,
		CrawlLimit:      crawlLimit,
		CrawlDepth:      crawlDepth,
		Headless:        headless,
		RateLimit:       rateLimit,
		UserAgent:       userAgent,
		Cookies:         cookies,
		CookieFile:      cookieFile,
		Concurrency:     concurrency,
		HostConcurrency: hostConcurrency,
		RespectRobots:   !ignoreRobots,
		GitHistory:      gitHistory,
		MaxScanLineLen:  maxScanLineLen,
	}

	var findings []finding.Finding

	if urlMode {
		findings, err = scanner.ScanURLs(allURLs, scanCfg)
	} else if pipe {
		findings, err = scanner.ScanReader(os.Stdin, scanCfg)
	} else {
		findings, err = scanner.ScanPaths(args, scanCfg)
	}
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	if gitHistory {
		repoPath := "."
		if len(args) > 0 {
			repoPath = args[0]
		}
		gitFindings, gErr := gitscan.ScanHistory(repoPath, scanCfg)
		if gErr == nil {
			findings = append(findings, gitFindings...)
		}
	}

	// --ignore-file: filter out known false positives by fingerprint
	if ignoreFile != "" {
		ignoreSet, iErr := ignore.LoadIgnoreFile(ignoreFile)
		if iErr != nil {
			return fmt.Errorf("load ignore file: %w", iErr)
		}
		findings = ignore.Filter(findings, ignoreSet)
	}

	// --validate: check if found secrets are live against provider APIs
	if validate {
		for i := range findings {
			if result, ok := validator.Validate(findings[i].RuleName, findings[i].Secret); ok {
				if !result.Valid {
					findings[i].Severity = finding.SeverityInfo
				}
			}
		}
	}

	// --verify: V1 state-path verification
	if verify {
		validator.SetRate(float64(verifyRate))
		for i := range findings {
			if result, ok := validator.Validate(findings[i].RuleName, findings[i].Secret); ok {
				if result.State == validator.StateVerified {
					findings[i].VerificationStatus = "VERIFIED"
				} else if result.State == validator.StateLikely || result.Valid {
					findings[i].VerificationStatus = "LIKELY"
				} else {
					findings[i].VerificationStatus = "POTENTIAL"
				}
			}
		}
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

	// --fail-on: CI gate — exit 1 only if findings meet severity threshold
	if failOn != "" {
		threshold := finding.ParseSeverity(failOn)
		for _, f := range findings {
			if f.Severity >= threshold {
				os.Exit(1)
			}
		}
		return nil
	}

	// default: exit 1 if any findings
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
