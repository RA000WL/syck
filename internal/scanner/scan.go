package scanner

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RA000WL/syck/internal/crawler"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/json_scanner"
	"github.com/RA000WL/syck/internal/jsrecon"
)

const maxEndpointBuf = 10 << 20

var textExtensions = map[string]bool{
	".txt": true, ".go": true, ".py": true, ".js": true, ".ts": true,
	".jsx": true, ".tsx": true, ".json": true, ".yaml": true, ".yml": true,
	".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".env": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true, ".bat": true,
	".ps1": true, ".rb": true, ".rs": true, ".java": true, ".kt": true,
	".swift": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true,
	".cs": true, ".php": true, ".pl": true, ".pm": true, ".lua": true,
	".r": true, ".scala": true, ".clj": true, ".hs": true, ".erl": true,
	".ex": true, ".exs": true, ".md": true, ".rst": true, ".html": true,
	".htm": true, ".xml": true, ".svg": true, ".css": true, ".scss": true,
	".less": true, ".sql": true, ".graphql": true, ".gql": true,
	".dockerfile": true, ".makefile": true, ".gradle": true,
	".tf": true, ".tfvars": true, ".hcl": true, ".properties": true,
	".lock": true, ".log": true, ".csv": true, ".tsv": true,
	".pem": true, ".key": true, ".cert": true, ".crt": true,
	".pgp": true, ".gpg": true, ".asc": true,
}

var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "__pycache__": true,
	"node_modules": true, ".venv": true, "venv": true, "env": true,
	".tox": true, ".eggs": true, "eggs": true, ".mypy_cache": true,
	".pytest_cache": true, ".cache": true, "target": true, "build": true,
	"dist": true, ".next": true, ".nuxt": true, ".output": true,
	"vendor": true, ".bundle": true, ".gradle": true, "bin": true,
	"obj": true, ".terraform": true, ".serverless": true,
}

// reportProgress fires the progress callback (if set) with the current file
// and findings counts. Safe to call concurrently.
func reportProgress(cfg Config, files *atomic.Int64, findings *atomic.Int64) {
	if cfg.Progress == nil {
		return
	}
	cfg.Progress(int(files.Load()), int(findings.Load()))
}

func ScanPaths(paths []string, cfg Config) ([]finding.Finding, error) {
	var (
		allFindings   []finding.Finding
		mu            sync.Mutex
		wg            sync.WaitGroup
		sem           = make(chan struct{}, cfg.Workers)
		filesScanned  atomic.Int64
		totalFindings atomic.Int64
	)

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			sem <- struct{}{}
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(path, cfg)
				filesScanned.Add(1)
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					totalFindings.Add(int64(len(findings)))
					mu.Unlock()
				}
				reportProgress(cfg, &filesScanned, &totalFindings)
			}(root)
			continue
		}

		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if cfg.Exclude != nil && cfg.Exclude.MatchString(path) {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !textExtensions[ext] && !isTextFile(path) {
				return nil
			}
			if info.Size() > cfg.MaxFileSize {
				return nil
			}

			sem <- struct{}{}
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(fp, cfg)
				filesScanned.Add(1)
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					totalFindings.Add(int64(len(findings)))
					mu.Unlock()
				}
				reportProgress(cfg, &filesScanned, &totalFindings)
			}(path)
			return nil
		})
		if err != nil {
			continue
		}
	}

	wg.Wait()

	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
	}

	if cfg.DowngradeFP {
		allFindings = DowngradeFP(allFindings)
	}

	return allFindings, nil
}

func ScanFile(path string, cfg Config) ([]finding.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Archive extraction — check before streaming to ensure full content is read
	if cfg.ScanArchives {
		ext := strings.ToLower(filepath.Ext(path))
		lower := strings.ToLower(path)
		if ext == ".zip" || ext == ".jar" || ext == ".war" || ext == ".ear" ||
			ext == ".tar" || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			members, err := crawler.ScanArchive(raw, path)
			if err != nil {
				return nil, nil
			}
			var findings []finding.Finding
			hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
			for _, m := range members {
				mFindings := scanContent(m.Content, m.Path+" ($archive: "+filepath.Base(path)+")", cfg, "archive_", nil, hasDecoders)
				findings = append(findings, mFindings...)
			}
			return findings, nil
		}
	}

	// Streaming mode for files >1MB to avoid loading entire content
	if info.Size() > 1024*1024 {
		return scanFileStreaming(path, cfg)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	gzipScanned := make(map[string]bool)
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL

	if cfg.DecodeGzip && len(raw) > 64 {
		if decompressed, ok := decoder.DecodeFileContent(raw); ok {
			gzipFindings := scanContent(string(decompressed), path, cfg, "gzip_", nil, hasDecoders)
			for _, f := range gzipFindings {
				key := f.Secret
				if len(key) > 60 {
					key = key[:60]
				}
				gzipScanned[key] = true
			}
			findings = append(findings, gzipFindings...)
		}
	}

	content := string(raw)
	findings = append(findings, scanContent(content, path, cfg, "", gzipScanned, hasDecoders)...)

	// JSON-aware scan for .json files
	jsonFindings := json_scanner.ScanJSONFile(path, content, cfg.Rules, cfg.MinSeverity)
	if skipSecrets := gzipScanned; skipSecrets != nil && len(jsonFindings) > 0 {
		var filtered []finding.Finding
		for _, f := range jsonFindings {
			key := f.Secret
			if len(key) > 60 {
				key = key[:60]
			}
			if !skipSecrets[key] {
				filtered = append(filtered, f)
			}
		}
		jsonFindings = filtered
	}
	findings = append(findings, jsonFindings...)

	if cfg.JSReconstruct && content != "" {
		jsFindings := jsrecon.ReconstructAndScan(content, path, cfg.Rules, cfg.MinSeverity)
		findings = append(findings, jsFindings...)
	}

	// Endpoint extraction
	if cfg.Endpoints && content != "" {
		eps := endpoints.ExtractEndpoints(path, content)
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
	}

	return findings, nil
}

func ScanContent(content string, path string, cfg Config) []finding.Finding {
	var findings []finding.Finding
	gzipScanned := make(map[string]bool)
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL

	findings = append(findings, scanContent(content, path, cfg, "", gzipScanned, hasDecoders)...)

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		jsonFindings := json_scanner.ScanJSONFile(path, content, cfg.Rules, cfg.MinSeverity)
		findings = append(findings, jsonFindings...)
	}

	if cfg.JSReconstruct && content != "" {
		jsFindings := jsrecon.ReconstructAndScan(content, path, cfg.Rules, cfg.MinSeverity)
		findings = append(findings, jsFindings...)
	}

	if cfg.Endpoints && content != "" {
		eps := endpoints.ExtractEndpoints(path, content)
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
	}

	return findings
}

func scanFileStreaming(path string, cfg Config) ([]finding.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []finding.Finding
	lineNum := 0
	var prevLine string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
	df := decoder.Flags{
		Base64:  cfg.DecodeBase64,
		Hex:     cfg.DecodeHex,
		Unicode: cfg.DecodeUnicode,
		URL:     cfg.DecodeURL,
	}

	// Accumulate content for endpoint extraction (up to 10MB to avoid OOM)
	var contentBuf strings.Builder
	needsEndpoint := cfg.Endpoints

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if needsEndpoint && contentBuf.Len() < maxEndpointBuf {
			if contentBuf.Len() > 0 {
				contentBuf.WriteString("\n")
			}
			if contentBuf.Len()+len(line) > maxEndpointBuf {
				contentBuf.WriteString(line[:maxEndpointBuf-contentBuf.Len()])
			} else {
				contentBuf.WriteString(line)
			}
		}

		var ctxBefore string
		if lineNum > 1 {
			ctxBefore = strings.TrimSpace(prevLine)
		}

		for _, rule := range cfg.Rules.Rules {
			matches := rule.MatchAll(line)
			for _, m := range matches {
				var secret string
				if m[1] <= len(line) {
					secret = line[m[0]:m[1]]
				} else {
					secret = line[m[0]:]
				}

				sev := finding.ParseSeverity(rule.Severity)
				if sev < cfg.MinSeverity {
					continue
				}

				e := entropy.Shannon(secret)
				if e < 2.0 {
					continue
				}

				findings = append(findings, finding.Finding{
					File:          path,
					Line:          lineNum,
					Column:        m[0],
					RuleName:      rule.Name,
					Severity:      sev,
					Secret:        secret,
					Context:       finding.Truncate(strings.TrimSpace(line)),
					ContextBefore: finding.Truncate(ctxBefore),
					Entropy:       e,
				})
			}
		}
		// Entropy token scan

		if entropy.HasSecretContext(line) {
			for _, tok := range entropy.EntropyTokenRe.FindAllString(line, -1) {
				if !entropy.IsEntropyTokenMatch(tok) {
					continue
				}
				col := strings.Index(line, tok)
				if col < 0 {
					col = 0
				}
				findings = append(findings, finding.Finding{
					File:          path,
					Line:          lineNum,
					Column:        col,
					RuleName:      "high_entropy_token",
					Severity:      finding.SeverityMedium,
					Secret:        tok,
					Context:       finding.Truncate(strings.TrimSpace(line)),
					ContextBefore: finding.Truncate(ctxBefore),
					Entropy:       entropy.Shannon(tok),
				})
			}
		}

		if hasDecoders {
			findings = append(findings, decoder.DecodeAndRescan(line, path, lineNum,
				cfg.Rules, cfg.MinSeverity, df)...)
		}

		prevLine = line
	}

	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("%s: scanner error: %w", path, err)
	}

	if needsEndpoint && contentBuf.Len() > 0 {
		fullContent := contentBuf.String()
		eps := endpoints.ExtractEndpoints(path, fullContent)
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
	}

	return findings, nil
}

func scanContent(content string, path string, cfg Config, tagPrefix string,
	skipSecrets map[string]bool, hasDecoders bool) []finding.Finding {
	var findings []finding.Finding
	var longLineCount int
	lines := strings.Split(content, "\n")

	df := decoder.Flags{
		Base64:  cfg.DecodeBase64,
		Hex:     cfg.DecodeHex,
		Unicode: cfg.DecodeUnicode,
		URL:     cfg.DecodeURL,
	}

	for lineNum, line := range lines {
		lineNum++

		if cfg.MaxScanLineLen > 0 && len(line) > cfg.MaxScanLineLen {
			if cfg.Debug {
				longLineCount++
				if longLineCount <= 10 {
					fmt.Fprintf(os.Stderr, "[debug] skipping long line (%d bytes) in %s:%d\n",
						len(line), path, lineNum)
				}
			}
			continue
		}

		// ContextBefore/After
		var ctxBefore, ctxAfter string
		if lineNum > 1 {
			ctxBefore = finding.Truncate(strings.TrimSpace(lines[lineNum-2]))
		}
		if lineNum < len(lines) {
			ctxAfter = finding.Truncate(strings.TrimSpace(lines[lineNum]))
		}

		for _, rule := range cfg.Rules.Rules {
			matches := rule.MatchAll(line)
			for _, m := range matches {
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

				sev := finding.ParseSeverity(rule.Severity)
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

				findings = append(findings, finding.Finding{
					File:          path,
					Line:          lineNum,
					Column:        m[0],
					RuleName:      ruleName,
					Severity:      sev,
					Secret:        secret,
					Context:       ctx,
					ContextBefore: ctxBefore,
					ContextAfter:  ctxAfter,
					Entropy:       e,
				})
			}
		}
		// Entropy token scan — only on lines with secret-context keywords

		if entropy.HasSecretContext(line) {
			for _, tok := range entropy.EntropyTokenRe.FindAllString(line, -1) {
				if !entropy.IsEntropyTokenMatch(tok) {
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
					File:          path,
					Line:          lineNum,
					Column:        col,
					RuleName:      "high_entropy_token",
					Severity:      finding.SeverityMedium,
					Secret:        tok,
					Context:       ctx,
					ContextBefore: ctxBefore,
					ContextAfter:  ctxAfter,
					Entropy:       entropy.Shannon(tok),
				})
			}
		}

		if hasDecoders {
			decodedFindings := decoder.DecodeAndRescan(line, path, lineNum,
				cfg.Rules, cfg.MinSeverity, df)
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
			findings = append(findings, decodedFindings...)
		}
	}

	return findings
}

func ScanReader(r *os.File, cfg Config) ([]finding.Finding, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))

	var linesBuf strings.Builder
	for scanner.Scan() {
		text := scanner.Text()
		if linesBuf.Len() > 0 {
			linesBuf.WriteString("\n")
		}
		if linesBuf.Len()+len(text) > maxEndpointBuf {
			linesBuf.WriteString(text[:maxEndpointBuf-linesBuf.Len()])
			break
		}
		linesBuf.WriteString(text)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("stdin: scanner error: %w", err)
	}

	content := linesBuf.String()
	findings := scanContent(content, "stdin", cfg, "", nil, false)

	// Endpoint extraction for stdin
	if cfg.Endpoints && content != "" {
		eps := endpoints.ExtractEndpoints("stdin", content)
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
	}

	if cfg.JSReconstruct && content != "" {
		jsFindings := jsrecon.ReconstructAndScan(content, "stdin", cfg.Rules, cfg.MinSeverity)
		findings = append(findings, jsFindings...)
	}

	if cfg.Progress != nil {
		cfg.Progress(1, len(findings))
	}

	return findings, nil
}

func ScanURLs(urls []string, cfg Config) ([]finding.Finding, error) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

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

	crawled := crawler.Crawl(urls, crawlCfg)

	var (
		allFindings   []finding.Finding
		urlsScanned   atomic.Int64
		totalFindings atomic.Int64
	)

	// V1.1: juicy file probing after BFS
	if cfg.ProbeJuicyFiles && len(crawled) > 0 {
		firstURL := crawled[0].URL
		baseURL := baseOf(firstURL)
		if baseURL != "" {
			juicyCfg := crawler.JuicyConfig{
				Client:    httpClient,
				BaseURL:   baseURL,
				UserAgent: cfg.UserAgent,
			}
			for _, jf := range crawler.ProbeJuicy(juicyCfg) {
				allFindings = append(allFindings, jf.ToFinding())
			}
		}
	}

	for _, c := range crawled {
		hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
		findings := scanContent(c.Content, c.URL, cfg, "", nil, hasDecoders)
		allFindings = append(allFindings, findings...)
		urlsScanned.Add(1)
		totalFindings.Add(int64(len(findings)))

		// Endpoint extraction for crawled URLs
		if cfg.Endpoints && c.Content != "" {
			eps := endpoints.ExtractEndpoints(c.URL, c.Content)
			for _, ep := range eps {
				score := endpoints.ComputeRiskScore(ep.Endpoint)
				if cfg.MinEndpointScore > 0 && score < cfg.MinEndpointScore {
					continue
				}
				allFindings = append(allFindings, finding.Finding{
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
		}

		// V1.1: emit source_map finding for harvested .js.map files
		if cfg.Endpoints && strings.HasSuffix(c.URL, ".js.map") {
			allFindings = append(allFindings, finding.Finding{
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

		if cfg.Progress != nil {
			cfg.Progress(int(urlsScanned.Load()), int(totalFindings.Load()))
		}
	}

	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
	}
	if cfg.DowngradeFP {
		allFindings = DowngradeFP(allFindings)
	}

	return allFindings, nil
}

func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, 512)
	n, err := reader.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	buf = buf[:n]

	for _, b := range buf {
		if b == 0 {
			return false
		}
	}
	return true
}

// baseOf returns the scheme+host portion of a URL.
func baseOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func contextLabel(tagPrefix string) string {
	switch tagPrefix {
	case "archive_":
		return "archive: "
	default:
		return "gzip decoded: "
	}
}
