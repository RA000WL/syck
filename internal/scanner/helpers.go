package scanner

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/RA000WL/syck/internal/crawler"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/httpclient"
	"github.com/RA000WL/syck/internal/recon"
	"github.com/RA000WL/syck/internal/sourcemap"
)

// buildHTTPClient creates an HTTP client with custom headers and cookies
func buildHTTPClient(cfg Config) *http.Client {
	httpClient := httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)

	if len(cfg.Headers) > 0 || cfg.CookieString != "" {
		effectiveHeaders := make(map[string][]string)
		for k, vals := range cfg.Headers {
			effectiveHeaders[k] = vals
		}
		if cfg.CookieString != "" {
			for _, c := range ParseCookies(cfg.CookieString) {
				effectiveHeaders["Cookie"] = append(effectiveHeaders["Cookie"], c.String())
			}
		}
		httpClient.Transport = &headerTransport{
			base:    httpClient.Transport,
			headers: effectiveHeaders,
		}
	}

	return httpClient
}

// buildCrawlConfig creates a crawler configuration from scan config
func buildCrawlConfig(cfg Config, httpClient *http.Client) crawler.CrawlConfig {
	crawlCfg := crawler.CrawlConfig{
		Scope:           cfg.Scope,
		Limit:           cfg.CrawlLimit,
		MaxDepth:        cfg.CrawlDepth,
		Debug:           cfg.Debug,
		Endpoints:       cfg.Endpoints,
		Headless:        cfg.Headless,
		RateLimit:       cfg.RateLimit,
		UserAgent:       cfg.UserAgent,
		Cookies:         cfg.Cookies,
		CookieFile:      cfg.CookieFile,
		Concurrency:     cfg.Concurrency,
		HostConcurrency: cfg.HostConcurrency,
		RespectRobots:   cfg.RespectRobots,
		SameDomainOnly:  true,
		HTTPClient:      httpClient,
	}

	if cfg.URLCacheDB != "" {
		if urlCache, uErr := crawler.OpenURLCache(cfg.URLCacheDB); uErr == nil {
			crawlCfg.URLCache = urlCache
		}
	}

	return crawlCfg
}

// probeJuicyFiles probes for high-value paths and returns findings
func probeJuicyFiles(httpClient *http.Client, crawled []crawler.CrawledURL, cfg Config) []finding.Finding {
	var findings []finding.Finding

	if !cfg.ProbeJuicyFiles || len(crawled) == 0 {
		return findings
	}

	firstURL := crawled[0].URL
	baseURL := baseOf(firstURL)
	if baseURL == "" {
		return findings
	}

	juicyCfg := crawler.JuicyConfig{
		Client:    httpClient,
		BaseURL:   baseURL,
		UserAgent: cfg.UserAgent,
	}

	for _, jf := range crawler.ProbeJuicy(juicyCfg) {
		findings = append(findings, jf.ToFinding())
	}

	return findings
}

// scanCrawledContent scans all crawled URLs for secrets and returns findings
func scanCrawledContent(crawled []crawler.CrawledURL, cfg Config, urlsScanned, totalFindings *int64) []finding.Finding {
	var findings []finding.Finding

	for _, c := range crawled {
		if cfg.URLProgress != nil {
			cfg.URLProgress(c.URL, nil, false)
		}

		hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
		itemFindings := scanContent(c.Content, c.URL, cfg, "", nil, hasDecoders)
		findings = append(findings, itemFindings...)
		*urlsScanned++
		*totalFindings += int64(len(itemFindings))

		if cfg.Progress != nil {
			cfg.Progress(int(*urlsScanned), int(*totalFindings))
		}
		if cfg.URLProgress != nil {
			cfg.URLProgress(c.URL, itemFindings, false)
		}
	}

	return findings
}

// extractEndpointsFromCrawl extracts API endpoints from crawled content
func extractEndpointsFromCrawl(crawled []crawler.CrawledURL, cfg Config) []finding.Finding {
	var findings []finding.Finding

	if !cfg.Endpoints {
		return findings
	}

	for _, c := range crawled {
		if c.Content == "" {
			continue
		}

		// Extract endpoints
		eps := endpoints.ExtractEndpoints(c.URL, c.Content)
		for _, ep := range eps {
			score := endpoints.ComputeRiskScore(ep.Endpoint)
			if cfg.MinEndpointScore > 0 && score < cfg.MinEndpointScore {
				continue
			}
			findings = append(findings, finding.Finding{
				File:      ep.File,
				Line:      ep.Line,
				Column:    0,
				RuleName:  "endpoint",
				Severity:  finding.SeverityInfo,
				RiskScore: score,
				Secret:    ep.Endpoint,
				Context:   ep.Context,
				Entropy:   0.0,
			})
		}

		// Emit source_map finding for harvested .js.map files
		if strings.HasSuffix(c.URL, ".js.map") {
			findings = append(findings, finding.Finding{
				File:     c.URL,
				Line:     1,
				Column:   0,
				RuleName: "source_map",
				Severity: finding.SeverityInfo,
				Secret:   c.URL,
				Context:  "source map harvested from " + strings.TrimSuffix(c.URL, ".map"),
				Entropy:  0.0,
			})
		}
	}

	return findings
}

// detectCloudStorage finds cloud storage URLs in crawled content
func detectCloudStorage(crawled []crawler.CrawledURL) []finding.Finding {
	var findings []finding.Finding

	for _, c := range crawled {
		if c.Content == "" {
			continue
		}
		for _, ref := range crawler.ExtractCloudStorage(c.Content) {
			findings = append(findings, finding.Finding{
				File:     c.URL,
				Line:     1,
				RuleName: "cloud_storage_" + ref.Provider,
				Severity: finding.SeverityMedium,
				Secret:   ref.URL,
				Context:  fmt.Sprintf("cloud storage reference: %s", ref.URL),
			})
		}
	}

	return findings
}

// probeGraphQLEndpoints probes GraphQL endpoints for introspection
func probeGraphQLEndpoints(httpClient *http.Client, crawled []crawler.CrawledURL, cfg Config) []finding.Finding {
	var findings []finding.Finding

	if !cfg.ProbeGraphQL || len(crawled) == 0 {
		return findings
	}

	for _, c := range crawled {
		if !strings.Contains(c.Content, "graphql") {
			continue
		}
		result, err := crawler.ProbeGraphQLIntrospection(httpClient, c.URL, 10*time.Second)
		if err != nil {
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] graphql introspection %s: %v\n", c.URL, err)
			}
			continue
		}
		findings = append(findings, finding.Finding{
			File:     c.URL,
			Line:     1,
			RuleName: "graphql_introspection",
			Severity: finding.SeverityHigh,
			Secret:   c.URL,
			Context:  fmt.Sprintf("introspection enabled: %d types, queries=%v, mutations=%v", len(result.Types), result.Queries, result.Mutations),
		})
	}

	return findings
}

// parseOpenAPISpecs parses OpenAPI/Swagger specs and extracts endpoints
func parseOpenAPISpecs(crawled []crawler.CrawledURL, cfg Config) []finding.Finding {
	var findings []finding.Finding

	if !cfg.ParseOpenAPI {
		return findings
	}

	for _, c := range crawled {
		if c.Content == "" {
			continue
		}
		if !strings.HasSuffix(c.URL, ".json") && !strings.HasSuffix(c.URL, ".yaml") && !strings.HasSuffix(c.URL, ".yml") {
			continue
		}
		spec, err := crawler.ParseOpenAPI(c.Content)
		if err != nil {
			continue
		}
		paths := spec.ExtractEndpointURLs(c.URL)
		for _, ep := range paths {
			score := endpoints.ComputeRiskScore(ep)
			if cfg.MinEndpointScore > 0 && score < cfg.MinEndpointScore {
				continue
			}
			findings = append(findings, finding.Finding{
				File:      c.URL,
				Line:      1,
				RuleName:  "openapi_endpoint",
				Severity:  finding.SeverityMedium,
				RiskScore: score,
				Secret:    ep,
				Context:   fmt.Sprintf("OpenAPI spec: %s %s", spec.Info.Title, spec.Info.Version),
			})
		}
	}

	return findings
}

// analyzeSecurityHeaders analyzes HTTP security headers
func analyzeSecurityHeaders(httpClient *http.Client, crawled []crawler.CrawledURL) []finding.Finding {
	var findings []finding.Finding

	if len(crawled) == 0 {
		return findings
	}

	headerDetector := recon.NewSecurityHeaderDetector(httpClient)
	crawledURLs := make([]string, 0, len(crawled))
	for _, c := range crawled {
		crawledURLs = append(crawledURLs, c.URL)
	}

	for _, sf := range headerDetector.Detect(crawledURLs) {
		findings = append(findings, finding.Finding{
			File:           sf.URL,
			Line:           1,
			RuleName:       "attack_surface_" + sf.Category,
			Severity:       sf.Severity,
			ConfidenceBand: "HIGH",
			Context:        sf.Category + ": " + sf.URL,
		})
	}

	return findings
}

// detectTechnologies detects web technologies from HTTP responses
func detectTechnologies(httpClient *http.Client, crawled []crawler.CrawledURL) []finding.Finding {
	var findings []finding.Finding

	if len(crawled) == 0 {
		return findings
	}

	techDetector := recon.NewTechFingerprintWeb(httpClient)
	crawledURLs := make([]string, 0, len(crawled))
	for _, c := range crawled {
		crawledURLs = append(crawledURLs, c.URL)
	}

	for _, sf := range techDetector.Detect(crawledURLs) {
		findings = append(findings, finding.Finding{
			File:           sf.URL,
			Line:           1,
			RuleName:       sf.Source,
			Severity:       sf.Severity,
			ConfidenceBand: confidenceBandFromScore(sf.Confidence),
			Context:        fmt.Sprintf("%s: %s (confidence=%d)", sf.Category, sf.URL, sf.Confidence),
			Confidence:     sf.Confidence,
		})
	}

	return findings
}

// detectWAF detects WAF/CDN protection
func detectWAF(httpClient *http.Client, crawled []crawler.CrawledURL) []finding.Finding {
	var findings []finding.Finding

	if len(crawled) == 0 {
		return findings
	}

	wafDetector := recon.NewWAFDetector(httpClient)
	crawledURLs := make([]string, 0, len(crawled))
	for _, c := range crawled {
		crawledURLs = append(crawledURLs, c.URL)
	}

	for _, sf := range wafDetector.Detect(crawledURLs) {
		findings = append(findings, finding.Finding{
			File:     sf.URL,
			Line:     1,
			RuleName: sf.Source,
			Severity: sf.Severity,
			Context:  sf.Category + ": " + sf.URL,
		})
	}

	return findings
}

// analyzeSourceMaps analyzes JavaScript files for source maps and extracts secrets
func analyzeSourceMaps(httpClient *http.Client, crawled []crawler.CrawledURL, cfg Config) []finding.Finding {
	var findings []finding.Finding

	for _, c := range crawled {
		if c.Content == "" {
			continue
		}

		// Check if this is a JavaScript file
		if !strings.HasSuffix(c.URL, ".js") && !strings.HasSuffix(c.URL, ".mjs") && !strings.HasSuffix(c.URL, ".cjs") {
			continue
		}

		// Look for sourceMappingURL
		mapURL := sourcemap.GetMapURL(c.Content)
		if mapURL == "" {
			continue
		}

		// Resolve relative URLs
		if !strings.HasPrefix(mapURL, "http://") && !strings.HasPrefix(mapURL, "https://") {
			baseURL := c.URL
			if idx := strings.LastIndex(baseURL, "/"); idx > 0 {
				baseURL = baseURL[:idx+1]
			}
			mapURL = baseURL + mapURL
		}

		// Fetch and parse source map
		sm, err := sourcemap.FetchAndParseSourceMap(httpClient, mapURL)
		if err != nil {
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] source map fetch %s: %v\n", mapURL, err)
			}
			continue
		}

		// Report source map found
		files := sm.ExtractFiles()
		if len(files) > 0 {
			sourceFiles := make([]string, 0, len(files))
			for _, f := range files {
				sourceFiles = append(sourceFiles, f.OriginalPath)
			}

			findings = append(findings, finding.Finding{
				File:     c.URL,
				Line:     1,
				RuleName: "source_map_exposed",
				Severity: finding.SeverityMedium,
				Secret:   mapURL,
				Context:  fmt.Sprintf("source map exposes %d original files: %s", len(files), truncateStrings(sourceFiles, 3)),
			})

			// Check for sensitive filenames
			secrets := sm.ExtractSecrets()
			for _, secret := range secrets {
				findings = append(findings, finding.Finding{
					File:     c.URL,
					Line:     1,
					RuleName: "source_map_sensitive_file",
					Severity: finding.SeverityHigh,
					Secret:   secret.SourceFile,
					Context:  secret.Reason,
				})
			}
		}
	}

	return findings
}

// truncateStrings truncates a slice of strings to maxItems with "..." suffix
func truncateStrings(strs []string, maxItems int) string {
	if len(strs) <= maxItems {
		return strings.Join(strs, ", ")
	}
	return strings.Join(strs[:maxItems], ", ") + fmt.Sprintf("... and %d more", len(strs)-maxItems)
}

// scanLineForRegexRules scans a single line against all regex rules
func scanLineForRegexRules(line string, lineNum int, path string, cfg Config, tagPrefix string, skipSecrets map[string]bool) []finding.Finding {
	var findings []finding.Finding

	for _, rule := range cfg.Rules.Rules {
		matches := rule.MatchAll(line)
		for _, m := range matches {
			if rule.RequiresContext && !lineHasContextKeyword(line, rule.ContextKeywords) {
				continue
			}
			var secret string
			if m[1] <= len(line) {
				secret = line[m[0]:m[1]]
			} else {
				secret = line[m[0]:]
			}

			if skipSecrets != nil {
				key := secret
				if len(key) > 60 {
					key = key[:60]
				}
				if skipSecrets[key] {
					continue
				}
			}

			sev := rule.SeverityInt
			if sev < cfg.MinSeverity {
				continue
			}

			e := entropy.Shannon(secret)
			if e < 2.0 {
				continue
			}

			ruleName := rule.Name
			ctx := strings.TrimSpace(line)
			if tagPrefix != "" {
				ruleName = tagPrefix + ruleName
				ctx = contextLabel(tagPrefix) + ctx
			}
			ctx = finding.Truncate(ctx)

			conf := finding.ConfidenceRegex
			method := "regex"
			if tagPrefix != "" {
				conf += finding.ConfidenceDecoded
				method = "decoded_regex"
			}

			findings = append(findings, finding.Finding{
				File:            path,
				Line:            lineNum,
				Column:          m[0],
				RuleName:        ruleName,
				Severity:        sev,
				Secret:          secret,
				Context:         ctx,
				ContextBefore:   "",
				ContextAfter:    "",
				Entropy:         e,
				Confidence:      conf,
				DetectionMethod: method,
			})
		}
	}

	return findings
}

// scanLineForEntropyTokens scans a single line for high-entropy tokens
func scanLineForEntropyTokens(line string, lineNum int, path string, cfg Config, tagPrefix string, skipSecrets map[string]bool, ctxBefore, ctxAfter string) []finding.Finding {
	var findings []finding.Finding

	if !entropy.HasSecretContext(line) {
		return findings
	}

	for _, tok := range entropy.EntropyTokenRe.FindAllString(line, -1) {
		ok, tokEntropy := checkEntropyToken(tok, cfg.EntropyThresholds)
		if !ok {
			continue
		}
		if skipSecrets != nil {
			key := tok
			if len(key) > 60 {
				key = key[:60]
			}
			if skipSecrets[key] {
				continue
			}
		}
		if entropy.IsMediaToken(tok) {
			continue
		}
		col := strings.Index(line, tok)
		if col < 0 {
			col = 0
		}
		ctx := strings.TrimSpace(line)
		if tagPrefix != "" {
			ctx = contextLabel(tagPrefix) + ctx
		}
		ctx = finding.Truncate(ctx)
		findings = append(findings, finding.Finding{
			File:            path,
			Line:            lineNum,
			Column:          col,
			RuleName:        "high_entropy_token",
			Severity:        finding.SeverityMedium,
			Secret:          tok,
			Context:         ctx,
			ContextBefore:   ctxBefore,
			ContextAfter:    ctxAfter,
			Entropy:         tokEntropy,
			Confidence:      finding.ConfidenceEntropy + finding.ConfidenceContext,
			DetectionMethod: "entropy+context",
		})
	}

	return findings
}

// scanLineForContextualSecrets scans a single line for contextual secrets
func scanLineForContextualSecrets(line string, lineNum int, path string) []finding.Finding {
	var findings []finding.Finding

	for _, cs := range entropy.ExtractContextualSecrets(line, 4.5) {
		if entropy.IsMediaToken(cs.Token) {
			continue
		}
		findings = append(findings, finding.Finding{
			File:            path,
			Line:            lineNum,
			Column:          strings.Index(line, cs.Token),
			RuleName:        "contextual_entropy_secret",
			Severity:        finding.SeverityHigh,
			Secret:          cs.Token,
			Context:         finding.Truncate(strings.TrimSpace(line)),
			Entropy:         cs.Entropy,
			Confidence:      finding.ConfidenceEntropy + finding.ConfidenceContext,
			DetectionMethod: "entropy+context",
		})
	}

	return findings
}

// scanLineForDecodedContent scans decoded content for secrets
func scanLineForDecodedContent(line string, lineNum int, path string, cfg Config, tagPrefix string, skipSecrets map[string]bool, activeDec []decoder.Decoder) []finding.Finding {
	decodedFindings := decoder.DecodeAndRescanWithDecoders(line, path, lineNum,
		cfg.Rules, cfg.MinSeverity, activeDec)
	if tagPrefix != "" {
		for i := range decodedFindings {
			decodedFindings[i].RuleName = tagPrefix + decodedFindings[i].RuleName
		}
	}
	if skipSecrets != nil {
		var filtered []finding.Finding
		for _, f := range decodedFindings {
			key := f.Secret
			if len(key) > 60 {
				key = key[:60]
			}
			if !skipSecrets[key] {
				filtered = append(filtered, f)
			}
		}
		decodedFindings = filtered
	}

	return decodedFindings
}

// scanLineForAuthHeaders scans a single line for auth headers
func scanLineForAuthHeaders(line string, lineNum int, path string) []finding.Finding {
	return DetectAuthHeaders(line, path, lineNum)
}

// scanLineForURLSecrets scans a single line for URL secrets
func scanLineForURLSecrets(line string, lineNum int, path string) []finding.Finding {
	return ExtractURLSecrets(line, path, lineNum)
}

// getLineContext returns context before and after a line
func getLineContext(lines []string, lineNum int) (ctxBefore, ctxAfter string) {
	if lineNum > 1 {
		ctxBefore = finding.Truncate(strings.TrimSpace(lines[lineNum-2]))
	}
	if lineNum < len(lines) {
		ctxAfter = finding.Truncate(strings.TrimSpace(lines[lineNum]))
	}
	return
}
