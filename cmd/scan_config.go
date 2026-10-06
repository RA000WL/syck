package cmd

import (
	"bufio"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/RA000WL/syck/internal/scanner"
)

// errExitCode is a sentinel returned by runScan when findings should cause
// the process to exit with code 1. Using a returned error (instead of
// os.Exit(1) inline) lets deferred cleanup (e.g. progress bar Finish) run.
var errExitCode = errors.New("syck: findings present")
var errExitCritical = errors.New("syck: critical findings present")
var errScanError = errors.New("syck: scan error")

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
	rulesFile            string
	severityStr          string
	formatStr            string
	outputFile           string
	redact               bool
	noDedup              bool
	excludeStr           string
	quiet                bool
	workers              int
	maxFileSize          string
	decodeBase64         bool
	decodeHex            bool
	decodeUnicode        bool
	decodeURL            bool
	decodeGzip           bool
	decodeBase64URL      bool
	decodeJWT            bool
	decodeDoubleBase64   bool
	decodeCharCode       bool
	jsReconstruct        bool
	endpoints            bool
	pipe                 bool
	failOn               string
	downgradeFP          bool
	urlList              []string
	urlFile              string
	scopeStr             string
	crawlLimit           int
	crawlDepth           int
	headless             bool
	rateLimit            int
	userAgent            string
	cookies              bool
	cookieFile           string
	concurrency          int
	hostConcurrency      int
	ignoreRobots         bool
	gitHistory           bool
	validate             bool
	verify               bool
	verifyRate           int
	ignoreFile           string
	maxScanLineLen       int
	progressFlag         bool
	minEndpointScore     int
	noJuicyFiles         bool
	sensitiveOnly        bool
	scanArchives         bool
	scanBinaries         bool
	multiline            bool
	stripComments        bool
	detectAuthHeaders    bool
	probeGraphQL         bool
	parseOpenAPI         bool
	paramBrute           bool
	paramBruteWordlist   string
	allowPrivateIPs      bool
	entropyThresholds    map[string]string
	webhookURL           string
	webhookStyle         string
	allowInsecureWebhook bool
	cacheDB              string
	adaptiveFlag         bool
	proxyURL             string
	authToken            string
	headerList           []string
	scopeFile            string
	cookieString         string
	noSitemap            bool
	diffMode             bool
	httpTimeout          string
	headerCheck          bool
	techDetect           bool
	urlCacheDB           string
	scanRecon            bool
	scanReconWayback     bool
	scanReconLive        bool
	excludeDir           string
)

func init() {
	scanCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "custom rules YAML file")
	scanCmd.Flags().StringVarP(&severityStr, "severity", "s", "LOW", "minimum severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	scanCmd.Flags().StringVarP(&formatStr, "format", "f", "text", "output format (text, json, jsonl, sarif, markdown, csv, html)")
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
	scanCmd.Flags().BoolVar(&decodeBase64URL, "decode-base64url", false, "base64url decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeJWT, "decode-jwt", false, "jwt decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeDoubleBase64, "decode-double-base64", false, "double-base64 decode lines and rescan")
	scanCmd.Flags().BoolVar(&decodeCharCode, "decode-charcode", false, "charcode decode lines and rescan")
	scanCmd.Flags().BoolVar(&jsReconstruct, "js-reconstruct", true, "reconstruct JS concatenated strings")
	scanCmd.Flags().BoolVar(&endpoints, "endpoints", true, "extract API/graphql/websocket URLs")
	scanCmd.Flags().BoolVar(&pipe, "pipe", false, "scan from stdin")
	scanCmd.Flags().StringVar(&failOn, "fail-on", "", "CI gate: exit 1 if findings at or above this severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	scanCmd.Flags().BoolVar(&downgradeFP, "downgrade-fp", true, "downgrade severity for findings in test/mock/vendor dirs and placeholder patterns")

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
	scanCmd.Flags().IntVar(&maxScanLineLen, "max-scan-line-len", 0, "skip per-line scanning on lines exceeding this length (0=unlimited)")
	scanCmd.Flags().BoolVar(&progressFlag, "progress", false, "show TUI progress bar on stderr (auto-disabled by --quiet or --pipe)")
	scanCmd.Flags().IntVar(&minEndpointScore, "min-endpoint-score", 0, "minimum endpoint risk score (0-10); endpoints below are omitted")
	scanCmd.Flags().BoolVar(&noJuicyFiles, "no-juicy-files", false, "disable juicy file probing (default: enabled with --endpoints)")
	scanCmd.Flags().BoolVar(&sensitiveOnly, "sensitive-only", false, "deprecated: use --min-endpoint-score 5 (kept for backward compat)")
	scanCmd.Flags().BoolVar(&scanArchives, "scan-archives", false, "extract and scan inside archives (zip, tar, tar.gz, jar, war, ear)")
	scanCmd.Flags().BoolVar(&scanBinaries, "scan-binaries", false, "extract and scan strings from binary files")
	scanCmd.Flags().BoolVar(&multiline, "multiline", true, "enable multi-line pattern matching (sliding window)")
	scanCmd.Flags().BoolVar(&stripComments, "strip-comments", false, "strip comment lines before scanning")
	scanCmd.Flags().BoolVar(&detectAuthHeaders, "detect-auth-headers", true, "detect hardcoded Authorization headers and API keys")
	scanCmd.Flags().BoolVar(&probeGraphQL, "probe-graphql", false, "probe GraphQL endpoints with introspection query")
	scanCmd.Flags().BoolVar(&parseOpenAPI, "parse-openapi", false, "parse OpenAPI/Swagger specs and inject discovered endpoints")
	scanCmd.Flags().StringToStringVar(&entropyThresholds, "entropy-threshold", nil, "per-alphabet entropy threshold (hex=3.0,base64=4.2)")
	scanCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "send findings to this webhook URL")
	scanCmd.Flags().StringVar(&webhookStyle, "webhook-style", "json", "webhook payload style: slack, discord, or json (default json)")
	scanCmd.Flags().BoolVar(&allowInsecureWebhook, "allow-insecure-webhook", false, "allow http:// webhook URLs (secrets sent in plaintext; HTTPS is the default requirement)")
	scanCmd.Flags().StringVar(&cacheDB, "cache-db", "", "path to SQLite cache database for cross-run dedup")
	scanCmd.Flags().BoolVar(&adaptiveFlag, "adaptive", false, "enable adaptive confidence learning from past verdicts")
	scanCmd.Flags().StringVar(&proxyURL, "proxy", "", "HTTP proxy URL for all requests (e.g. http://127.0.0.1:8080)")
	scanCmd.Flags().StringVar(&authToken, "auth-token", "", "Bearer token for authenticated crawl requests")
	scanCmd.Flags().StringArrayVar(&headerList, "header", nil, "custom header in 'Name: Value' format (can be repeated)")
	scanCmd.Flags().StringVar(&scopeFile, "scope-file", "", "file with scope regex patterns (one per line, # comments)")
	scanCmd.Flags().StringVar(&cookieString, "cookie", "", "cookie string in 'name=value; name2=value2' format")
	scanCmd.Flags().BoolVar(&noSitemap, "no-sitemap", false, "disable robots.txt/sitemap.xml discovery")
	scanCmd.Flags().BoolVar(&diffMode, "diff", false, "only show new findings (requires --cache-db)")
	scanCmd.Flags().StringVar(&httpTimeout, "http-timeout", "10s", "HTTP client timeout (e.g. 10s, 30s)")
	scanCmd.Flags().BoolVar(&headerCheck, "header-check", true, "analyze HTTP security headers on discovered URLs (use --no-header-check to disable)")
	scanCmd.Flags().BoolVar(&techDetect, "tech-detect", true, "detect technologies from HTTP responses and source code (use --no-tech-detect to disable)")
	scanCmd.Flags().StringVar(&urlCacheDB, "url-cache-db", "", "path to SQLite URL cache database for cross-run crawl dedup")
	scanCmd.Flags().BoolVar(&scanRecon, "recon", false, "auto-discover subdomains before scanning (crt.sh)")
	scanCmd.Flags().BoolVar(&scanReconWayback, "recon-wayback", false, "include Wayback Machine URLs in recon")
	scanCmd.Flags().BoolVar(&scanReconLive, "recon-live", false, "only scan live hosts from recon")
	scanCmd.Flags().BoolVar(&paramBrute, "param-brute", false, "brute-force hidden parameters on discovered endpoints")
	scanCmd.Flags().StringVar(&paramBruteWordlist, "param-wordlist", "", "custom wordlist for parameter brute-force (one per line)")
	scanCmd.Flags().BoolVar(&allowPrivateIPs, "allow-private-ips", false, "allow secondary fetches and redirects to private IPs (disables SSRF guard)")
	scanCmd.Flags().StringVar(&excludeDir, "exclude-dir", "", "regex pattern to exclude directories (e.g. 'node_modules|vendor')")
}

// clampWorkers returns n when positive, otherwise a sane default of
// max(runtime.NumCPU(), 2) so a zero/negative --workers value never
// yields a zero-size worker pool. Delegates to scanner.EffectiveWorkers so
// the CLI and library callers share one definition.
func clampWorkers(n int) int {
	return scanner.EffectiveWorkers(n)
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

// loadWordlist loads a wordlist from a file (one word per line)
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if !seen[word] {
			seen[word] = true
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

func parseExcludeDir(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}
