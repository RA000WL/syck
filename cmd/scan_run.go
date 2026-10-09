package cmd

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/RA000WL/syck/config"
	"github.com/RA000WL/syck/internal/correlator"
	"github.com/RA000WL/syck/internal/discovery"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/formatters"
	"github.com/RA000WL/syck/internal/gitscan"
	"github.com/RA000WL/syck/internal/httpclient"
	"github.com/RA000WL/syck/internal/ignore"
	"github.com/RA000WL/syck/internal/parambrute"
	"github.com/RA000WL/syck/internal/progress"
	"github.com/RA000WL/syck/internal/rules"
	"github.com/RA000WL/syck/internal/scanner"
	"github.com/RA000WL/syck/internal/validator"
)

func runScan(cmd *cobra.Command, args []string) error {
	if sensitiveOnly {
		fmt.Fprintln(os.Stderr, "WARNING: --sensitive-only is deprecated, use --min-endpoint-score 5 instead")
		if minEndpointScore == 0 {
			minEndpointScore = 5
		}
	}

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

	// --recon: auto-discover subdomains before scanning
	if scanRecon {
		domain := ""
		if len(allURLs) > 0 {
			if u, err := url.Parse(allURLs[0]); err == nil {
				domain = u.Hostname()
			}
		} else if len(args) > 0 {
			domain = args[0]
		}
		if domain != "" {
			timeout, _ := time.ParseDuration(httpTimeout)
			client := httpclient.NewClient(timeout, proxyURL, false)

			fmt.Fprintf(os.Stderr, "[*] Recon: discovering subdomains for %s...\n", domain)
			subs, err := discovery.EnumerateSubdomains(domain, client, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  [!] crt.sh error: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  [+] Found %d subdomains\n", len(subs))
				for _, s := range subs {
					allURLs = append(allURLs, "https://"+s.Subdomain)
					fmt.Fprintf(os.Stderr, "      %s\n", s.Subdomain)
				}
			}

			if scanReconWayback {
				fmt.Fprintf(os.Stderr, "[*] Recon: fetching Wayback Machine URLs...\n")
				wayback, err := discovery.FetchWaybackURLs(domain, client, 500)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  [!] Wayback error: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "  [+] Found %d historical URLs\n", len(wayback))
					for _, w := range wayback {
						allURLs = append(allURLs, w.URL)
					}
				}
			}

			if scanReconLive {
				fmt.Fprintf(os.Stderr, "[*] Recon: checking live hosts...\n")
				hosts := discovery.HostsFromSubdomains(subs)
				hostResults := discovery.CheckLiveHosts(hosts, client, timeout)
				alive := discovery.FilterAliveHosts(hostResults)
				fmt.Fprintf(os.Stderr, "  [+] %d/%d hosts alive\n", len(alive), len(hosts))

				aliveSet := make(map[string]bool)
				for _, h := range alive {
					aliveSet[h] = true
				}
				var filtered []string
				for _, u := range allURLs {
					if parsed, err := url.Parse(u); err == nil {
						if aliveSet[parsed.Hostname()] {
							filtered = append(filtered, u)
						}
					}
				}
				allURLs = filtered
			}

			// Deduplicate
			seen := make(map[string]bool)
			var unique []string
			for _, u := range allURLs {
				if !seen[u] {
					seen[u] = true
					unique = append(unique, u)
				}
			}
			allURLs = unique

			fmt.Fprintf(os.Stderr, "[*] Recon complete: %d URLs to scan\n\n", len(allURLs))
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

	if _, ok := finding.SeverityFromName[severityStr]; !ok {
		return fmt.Errorf("invalid --severity %q: must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL", severityStr)
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

	// Parse --scope-file patterns
	var scopePatterns []*regexp.Regexp
	if scopeFile != "" {
		f, err := os.Open(scopeFile)
		if err != nil {
			return fmt.Errorf("open scope file: %w", err)
		}
		defer f.Close()
		sfScanner := bufio.NewScanner(f)
		for sfScanner.Scan() {
			line := strings.TrimSpace(sfScanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			re, err := regexp.Compile(line)
			if err != nil {
				return fmt.Errorf("invalid scope pattern %q: %w", line, err)
			}
			scopePatterns = append(scopePatterns, re)
		}
		if len(scopePatterns) == 0 {
			return fmt.Errorf("scope file %q contains no valid patterns", scopeFile)
		}
	}

	// Parse headers from --auth-token and --header flags
	headers := make(map[string][]string)
	if authToken != "" {
		headers["Authorization"] = append(headers["Authorization"], "Bearer "+authToken)
	}
	for _, h := range headerList {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --header format %q: expected 'Name: Value'", h)
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if name == "" || value == "" {
			return fmt.Errorf("invalid --header format %q: name and value required", h)
		}
		headers[name] = append(headers[name], value)
	}

	// Validate --diff requires --cache-db
	if diffMode && cacheDB == "" {
		return fmt.Errorf("--diff requires --cache-db for cross-run comparison")
	}

	// Parse --http-timeout
	parsedTimeout, err := time.ParseDuration(httpTimeout)
	if err != nil {
		return fmt.Errorf("invalid --http-timeout: %w", err)
	}
	if parsedTimeout < time.Second {
		parsedTimeout = time.Second
	}

	var entropyThresholdsParsed map[string]float64
	if len(entropyThresholds) > 0 {
		entropyThresholdsParsed = make(map[string]float64, len(entropyThresholds))
		for k, v := range entropyThresholds {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("invalid --entropy-threshold value for %q: %q (must be a float)", k, v)
			}
			entropyThresholdsParsed[k] = f
		}
	}

	scanCfg := scanner.Config{
		Workers:            clampWorkers(workers),
		MaxFileSize:        maxSize,
		Exclude:            excludeRegex,
		Rules:              rs,
		MinSeverity:        sev,
		NoDedup:            noDedup,
		Debug:              debugMode,
		DecodeBase64:       decodeBase64,
		DecodeHex:          decodeHex,
		DecodeUnicode:      decodeUnicode,
		DecodeURL:          decodeURL,
		DecodeGzip:         decodeGzip,
		DecodeBase64URL:    decodeBase64URL,
		DecodeJWT:          decodeJWT,
		DecodeDoubleBase64: decodeDoubleBase64,
		DecodeCharCode:     decodeCharCode,
		JSReconstruct:      jsReconstruct,
		Endpoints:          endpoints,
		DowngradeFP:        downgradeFP,
		URLs:               allURLs,
		URLFile:            urlFile,
		Scope:              scopeRegex,
		CrawlLimit:         crawlLimit,
		CrawlDepth:         crawlDepth,
		Headless:           headless,
		RateLimit:          rateLimit,
		UserAgent:          userAgent,
		Cookies:            cookies,
		CookieFile:         cookieFile,
		Concurrency:        concurrency,
		HostConcurrency:    hostConcurrency,
		RespectRobots:      !ignoreRobots,
		GitHistory:         gitHistory,
		MaxScanLineLen:     maxScanLineLen,
		MultiLine:          multiline,
		MinEndpointScore:   minEndpointScore,
		ProbeJuicyFiles:    endpoints && !noJuicyFiles,
		ScanArchives:       scanArchives,
		ScanBinaries:       scanBinaries,
		StripComments:      stripComments,
		DetectAuthHeaders:  detectAuthHeaders,
		ProbeGraphQL:       probeGraphQL,
		ParseOpenAPI:       parseOpenAPI,
		EntropyThresholds:  entropyThresholdsParsed,
		CacheDB:            cacheDB,
		Adaptive:           adaptiveFlag,
		HTTPTimeout:        parsedTimeout,
		ProxyURL:           proxyURL,
		Headers:            headers,
		ScopePatterns:      scopePatterns,
		Diff:               diffMode,
		CookieString:       cookieString,
		NoSitemap:          noSitemap,
		AllowPrivateIPs:    allowPrivateIPs,
		HeaderCheck:        headerCheck,
		TechDetect:         techDetect,
		URLCacheDB:         urlCacheDB,
		ExcludeDir:         parseExcludeDir(excludeDir),
		NoCorrelation:      noCorrelation,
	}

	if progressFlag && !quiet && !pipe {
		if urlMode {
			target := allURLs[0]
			scope := ""
			if scopeStr != "" {
				scope = scopeStr
			}
			progress.PrintBanner(os.Stderr, progress.BannerConfig{
				Target:       target,
				Scope:        scope,
				Workers:      concurrency,
				RateLimit:    rateLimit,
				CrawlLimit:   crawlLimit,
				CrawlDepth:   crawlDepth,
				Timeout:      httpTimeout,
				UserAgent:    userAgent,
				Headless:     headless,
				ExtractLinks: true,
				Endpoints:    endpoints,
				Proxy:        proxyURL,
				NoColor:      noColor,
			})
			up := progress.NewURLProgress(os.Stderr, len(allURLs))
			defer up.Finish()
			scanCfg.URLProgress = func(url string, findings []finding.Finding, done bool) {
				up.SetCurrentURL(url)
				if len(findings) > 0 {
					up.AddFindings(findings)
				}
				up.TickURL()
			}
		} else {
			bar := progress.New(os.Stderr)
			defer bar.Finish()
			scanCfg.Progress = bar.Tick
		}
	}

	if adaptiveFlag && cacheDB != "" {
		if c, cErr := correlator.OpenCache(cacheDB); cErr == nil {
			if w, wErr := c.LoadWeights(); wErr == nil {
				scanCfg.AdaptiveWeights = w
			}
			c.Close()
		}
	}

	var findings []finding.Finding

	if urlMode {
		findings, err = scanner.ScanURLs(allURLs, scanCfg)
	} else if pipe {
		// Read stdin and detect if it's URLs or raw content
		var pipeContent strings.Builder
		stdScanner := bufio.NewScanner(os.Stdin)
		buf := make([]byte, 1024*1024)
		stdScanner.Buffer(buf, len(buf))
		for stdScanner.Scan() {
			line := strings.TrimSpace(stdScanner.Text())
			if line != "" {
				pipeContent.WriteString(line)
				pipeContent.WriteString("\n")
			}
		}
		if err := stdScanner.Err(); err != nil {
			return fmt.Errorf("stdin read error: %w", err)
		}

		content := pipeContent.String()
		// Check if content is URLs (one per line)
		lines := strings.Split(content, "\n")
		var pipeURLs []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				pipeURLs = append(pipeURLs, line)
			}
		}

		if len(pipeURLs) > 0 {
			// Pipe contains URLs - fetch and scan them
			if scanCfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] pipe mode: detected %d URLs\n", len(pipeURLs))
			}
			findings, err = scanner.ScanURLs(pipeURLs, scanCfg)
		} else {
			// Pipe contains raw content - scan as text
			if scanCfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] pipe mode: scanning raw content (%d bytes)\n", len(content))
			}
			findings = scanner.ScanContent(content, "stdin", scanCfg)
		}
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
		} else {
			fmt.Fprintf(os.Stderr, "WARNING: git history scan failed: %v\n", gErr)
		}
	}

	// --param-brute: brute-force hidden parameters on discovered URLs
	if paramBrute && len(allURLs) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Parameter brute-force: testing %d URLs...\n", len(allURLs))
		httpClient := httpclient.NewClient(scanCfg.HTTPTimeout, scanCfg.ProxyURL, false)
		paramCfg := parambrute.DefaultConfig(httpClient)

		// Load custom wordlist if provided
		if paramBruteWordlist != "" {
			wl, wlErr := loadWordlist(paramBruteWordlist)
			if wlErr != nil {
				fmt.Fprintf(os.Stderr, "  [!] wordlist error: %v\n", wlErr)
			} else {
				paramCfg.Wordlist = wl
				fmt.Fprintf(os.Stderr, "  [+] Loaded %d parameters from wordlist\n", len(wl))
			}
		}

		for _, u := range allURLs {
			paramFindings := parambrute.BruteForce(u, paramCfg)
			for _, pf := range paramFindings {
				severity := finding.SeverityInfo
				if pf.Reflected {
					severity = finding.SeverityMedium
				}
				if pf.Interesting {
					severity = finding.SeverityHigh
				}
				findings = append(findings, finding.Finding{
					File:     u,
					Line:     1,
					RuleName: "hidden_parameter",
					Severity: severity,
					Secret:   pf.Parameter,
					Context:  pf.Reason,
				})
			}
			if len(paramFindings) > 0 {
				fmt.Fprintf(os.Stderr, "  [+] %s: found %d interesting parameters\n", u, len(paramFindings))
			}
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

	// Diff mode: only show new findings
	if diffMode {
		findings = scanner.FilterNewOnly(findings)
	}

	// --validate: check if found secrets are live against provider APIs
	if validate || verify {
		if proxyURL != "" {
			validator.InitValidatorClient(proxyURL)
		}
	}

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
		Version: Version,
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

	if webhookURL != "" {
		style := formatters.WebhookStyle(webhookStyle)
		var webhookOpts []formatters.WebhookOption
		if proxyURL != "" {
			webhookOpts = append(webhookOpts, formatters.WithProxy(proxyURL))
		}
		webhookOpts = append(webhookOpts,
			formatters.WithRedact(redact),
			formatters.WithAllowInsecure(allowInsecureWebhook),
		)
		if err := formatters.PostWebhook(webhookURL, style, findings, webhookOpts...); err != nil {
			fmt.Fprintf(os.Stderr, "warning: webhook error: %v\n", err)
		}
	}

	// --fail-on: CI gate — exit based on severity threshold
	if failOn != "" {
		if _, ok := finding.SeverityFromName[failOn]; !ok {
			return fmt.Errorf("invalid --fail-on %q: must be one of INFO, LOW, MEDIUM, HIGH, CRITICAL", failOn)
		}
		threshold := finding.ParseSeverity(failOn)
		for _, f := range findings {
			if f.Severity >= threshold {
				if f.Severity == finding.SeverityCritical {
					return errExitCritical
				}
				return errExitCode
			}
		}
		return nil
	}

	// default: exit 1 if any findings, exit 2 if CRITICAL
	if len(findings) > 0 {
		for _, f := range findings {
			if f.Severity == finding.SeverityCritical {
				return errExitCritical
			}
		}
		return errExitCode
	}
	return nil
}
