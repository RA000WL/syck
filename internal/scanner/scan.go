package scanner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/correlator"
	"github.com/RA000WL/syck/internal/crawler"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/fileutil"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/httpclient"
	"github.com/RA000WL/syck/internal/json_scanner"
	"github.com/RA000WL/syck/internal/jsrecon"
	"github.com/RA000WL/syck/internal/recon"
)

const maxEndpointBuf = 10 << 20

var streamingBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1024*1024)
		return &b
	},
}

var textExtensions = fileutil.TextExtensions

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
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] stat %s: %v\n", root, err)
			}
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
				if cfg.ScanBinaries {
					isBinaryExt := ext == ".exe" || ext == ".dll" || ext == ".so" ||
						ext == ".dylib" || ext == ".class" || ext == ".pyc" ||
						ext == ".o" || ext == ".obj" || ext == ".wasm"
					if isBinaryExt {
						sem <- struct{}{}
						wg.Add(1)
						go func(fp string) {
							defer wg.Done()
							defer func() { <-sem }()
							filesScanned.Add(1)
							f, e := ScanBinaryFile(fp, cfg)
							if e == nil && len(f) > 0 {
								mu.Lock()
								allFindings = append(allFindings, f...)
								totalFindings.Add(int64(len(f)))
								mu.Unlock()
							}
						}(path)
						return nil
					}
				}
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

	if cfg.CacheDB != "" {
		cache, err := correlator.OpenCache(cfg.CacheDB)
		if err == nil {
			for i := range allFindings {
				fp := correlator.Fingerprint(allFindings[i].RuleName, allFindings[i].Secret, allFindings[i].File)
				isNew, _ := cache.RecordWithMeta(fp, allFindings[i].RuleName, allFindings[i].Secret, allFindings[i].File)
				if isNew {
					allFindings[i].IsNew = true
				}
			}
			if cfg.Adaptive && cfg.AdaptiveWeights != nil {
				for i := range allFindings {
					filePattern := adaptive.ExtractFilePattern(allFindings[i].File)
					w := cfg.AdaptiveWeights.Get(allFindings[i].RuleName, filePattern)
					if w != nil {
						allFindings[i].AdaptiveModifier = int(w.Modifier)
						allFindings[i].LearningTier = w.Tier.Label()
					}
				}
			}
			cache.Close()
		}
	}

	return allFindings, nil
}

func ScanBinaryFile(path string, cfg Config) ([]finding.Finding, error) {
	strs, err := ExtractBinaryStrings(path)
	if err != nil || len(strs) == 0 {
		return nil, err
	}
	var findings []finding.Finding
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
	for _, s := range strs {
		findings = append(findings, scanContent(s.text, path+" (binary)", cfg, "binary_", nil, hasDecoders)...)
	}
	return findings, nil
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
				if cfg.Debug {
					fmt.Fprintf(os.Stderr, "[debug] archive scan %s: %v\n", path, err)
				}
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

	// V1.2: package manager file discovery
	if (cfg.Endpoints || cfg.ScanArchives) && content != "" {
		pkgs := crawler.ScanPackageFile(path, content)
		for _, p := range pkgs {
			if p.Secret != "" {
				findings = append(findings, finding.Finding{
					File: path, Line: p.Line, RuleName: "npm_auth_token",
					Severity: finding.SeverityHigh, Secret: p.Secret,
					Context: finding.Truncate(p.Name),
				})
			}
			if p.Mutable {
				findings = append(findings, finding.Finding{
					File: path, Line: p.Line, RuleName: "mutable_dependency",
					Severity: finding.SeverityLow, Secret: p.Name,
					Context: fmt.Sprintf("mutable %s dep in %s", p.Source, filepath.Base(path)),
				})
			}
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

	if cfg.Debug && (cfg.StripComments || cfg.MultiLine) {
		fmt.Fprintf(os.Stderr, "[debug] streaming mode for %s: StripComments/MultiLine not supported for files >1MB\n", path)
	}

	var findings []finding.Finding
	lineNum := 0
	var prevLine string
	scanner := bufio.NewScanner(f)
	bp := streamingBufPool.Get().(*[]byte)
	defer streamingBufPool.Put(bp)
	buf := *bp
	scanner.Buffer(buf, len(buf))
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL
	df := decoder.Flags{
		Base64:   cfg.DecodeBase64,
		Hex:      cfg.DecodeHex,
		Unicode:  cfg.DecodeUnicode,
		URL:      cfg.DecodeURL,
		Gzip:     cfg.DecodeGzip,
		CharCode: cfg.DecodeHex || cfg.DecodeUnicode,
	}
	var activeDec []decoder.Decoder
	if hasDecoders {
		activeDec = decoder.PrecomputeDecoders(df)
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
		// Note: ctxAfter unavailable in streaming mode — see scanContent for full context
		if lineNum > 1 {
			ctxBefore = strings.TrimSpace(prevLine)
		}

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

				sev := rule.SeverityInt
				if sev < cfg.MinSeverity {
					continue
				}

				e := entropy.Shannon(secret)
				if e < 2.0 {
					continue
				}

				findings = append(findings, finding.Finding{
					File:            path,
					Line:            lineNum,
					Column:          m[0],
					RuleName:        rule.Name,
					Severity:        sev,
					Secret:          secret,
					Context:         finding.Truncate(strings.TrimSpace(line)),
					ContextBefore:   finding.Truncate(ctxBefore),
					Entropy:         e,
					Confidence:      finding.ConfidenceRegex,
					DetectionMethod: "regex",
				})
			}
		}
		// Entropy token scan

		if entropy.HasSecretContext(line) {
			for _, tok := range entropy.EntropyTokenRe.FindAllString(line, -1) {
				ok, tokEntropy := checkEntropyToken(tok, cfg.EntropyThresholds)
				if !ok {
					continue
				}
				if entropy.IsMediaToken(tok) {
					continue
				}
				col := strings.Index(line, tok)
				if col < 0 {
					col = 0
				}
				findings = append(findings, finding.Finding{
					File:            path,
					Line:            lineNum,
					Column:          col,
					RuleName:        "high_entropy_token",
					Severity:        finding.SeverityMedium,
					Secret:          tok,
					Context:         finding.Truncate(strings.TrimSpace(line)),
					ContextBefore:   finding.Truncate(ctxBefore),
					Entropy:         tokEntropy,
					Confidence:      finding.ConfidenceEntropy + finding.ConfidenceContext,
					DetectionMethod: "entropy+context",
				})
			}
		}

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

		if hasDecoders {
			findings = append(findings, decoder.DecodeAndRescanWithDecoders(line, path, lineNum,
				cfg.Rules, cfg.MinSeverity, activeDec)...)
		}

		urlFindings := ExtractURLSecrets(line, path, lineNum)
		findings = append(findings, urlFindings...)

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

	if cfg.StripComments {
		content = StripLineComments(content)
	}
	lines := strings.Split(content, "\n")

	df := decoder.Flags{
		Base64:   cfg.DecodeBase64,
		Hex:      cfg.DecodeHex,
		Unicode:  cfg.DecodeUnicode,
		URL:      cfg.DecodeURL,
		Gzip:     cfg.DecodeGzip,
		CharCode: cfg.DecodeHex || cfg.DecodeUnicode,
	}
	var activeDec []decoder.Decoder
	if hasDecoders {
		activeDec = decoder.PrecomputeDecoders(df)
	}

	var mlScanner *MultiLineScanner
	if cfg.MultiLine {
		mlScanner = NewMultiLineScanner(cfg.Rules, cfg.MinSeverity)
	}
	mlSeen := map[string]bool{}

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
					ContextBefore:   ctxBefore,
					ContextAfter:    ctxAfter,
					Entropy:         e,
					Confidence:      conf,
					DetectionMethod: method,
				})
			}
		}
		// Multi-line pattern matching (sliding window)
		if cfg.MultiLine && lineNum >= 2 {
			windowStart := lineNum - maxMultiLineWindow
			if windowStart < 0 {
				windowStart = 0
			}
			mlFindings := mlScanner.ScanMultiLine(lines[windowStart:lineNum], path, windowStart+1)
			for _, f := range mlFindings {
				key := f.File + "|" + f.Secret + "|" + f.RuleName
				if !mlSeen[key] {
					mlSeen[key] = true
					findings = append(findings, f)
				}
			}
		}
		// Entropy token scan — only on lines with secret-context keywords

		if entropy.HasSecretContext(line) {
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
		}

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

		if hasDecoders {
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
			findings = append(findings, decodedFindings...)
		}

		if cfg.DetectAuthHeaders {
			findings = append(findings, DetectAuthHeaders(line, path, lineNum)...)
		}

		urlFindings := ExtractURLSecrets(line, path, lineNum)
		findings = append(findings, urlFindings...)
	}

	// Source technology fingerprinting
	if cfg.TechDetect {
		findings = append(findings, DetectSourceTech(content, path)...)
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

	if cfg.CacheDB != "" {
		if cache, err := correlator.OpenCache(cfg.CacheDB); err == nil {
			for i := range findings {
				fp := correlator.Fingerprint(findings[i].RuleName, findings[i].Secret, findings[i].File)
				if isNew, _ := cache.RecordWithMeta(fp, findings[i].RuleName, findings[i].Secret, findings[i].File); isNew {
					findings[i].IsNew = true
				}
			}
			if cfg.Adaptive && cfg.AdaptiveWeights != nil {
				for i := range findings {
					filePattern := adaptive.ExtractFilePattern(findings[i].File)
					w := cfg.AdaptiveWeights.Get(findings[i].RuleName, filePattern)
					if w != nil {
						findings[i].AdaptiveModifier = int(w.Modifier)
						findings[i].LearningTier = w.Tier.Label()
					}
				}
			}
			cache.Close()
		}
	}

	if cfg.Progress != nil {
		cfg.Progress(1, len(findings))
	}

	return findings, nil
}

func ScanURLs(urls []string, cfg Config) ([]finding.Finding, error) {
	httpClient := httpclient.NewClient(cfg.HTTPTimeout, cfg.ProxyURL, false)

	// Wire custom headers and cookies into crawl transport
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

	// Open URL cache if configured
	if cfg.URLCacheDB != "" {
		if urlCache, uErr := crawler.OpenURLCache(cfg.URLCacheDB); uErr == nil {
			defer urlCache.Close()
			crawlCfg.URLCache = urlCache
		}
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
		if cfg.URLProgress != nil {
			cfg.URLProgress(c.URL, nil, false)
		}

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
		if cfg.URLProgress != nil {
			cfg.URLProgress(c.URL, findings, false)
		}
	}

	// V1.2: cloud storage URL detection
	for _, c := range crawled {
		if c.Content == "" {
			continue
		}
		for _, ref := range crawler.ExtractCloudStorage(c.Content) {
			allFindings = append(allFindings, finding.Finding{
				File:     c.URL,
				Line:     1,
				RuleName: "cloud_storage_" + ref.Provider,
				Severity: finding.SeverityMedium,
				Secret:   ref.URL,
				Context:  fmt.Sprintf("cloud storage reference: %s", ref.URL),
			})
		}
	}

	// V1.2: GraphQL introspection probe
	if cfg.ProbeGraphQL && len(crawled) > 0 {
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
			allFindings = append(allFindings, finding.Finding{
				File:     c.URL,
				Line:     1,
				RuleName: "graphql_introspection",
				Severity: finding.SeverityHigh,
				Secret:   c.URL,
				Context:  fmt.Sprintf("introspection enabled: %d types, queries=%v, mutations=%v", len(result.Types), result.Queries, result.Mutations),
			})
		}
	}

	// V1.2: OpenAPI spec parsing
	if cfg.ParseOpenAPI {
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
				allFindings = append(allFindings, finding.Finding{
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
	}

	// Security header analysis on crawled URLs
	if cfg.HeaderCheck && len(crawled) > 0 {
		headerDetector := recon.NewSecurityHeaderDetector(httpClient)
		crawledURLs := make([]string, 0, len(crawled))
		for _, c := range crawled {
			crawledURLs = append(crawledURLs, c.URL)
		}
		for _, sf := range headerDetector.Detect(crawledURLs) {
			allFindings = append(allFindings, finding.Finding{
				File:           sf.URL,
				Line:           1,
				RuleName:       "attack_surface_" + sf.Category,
				Severity:       sf.Severity,
				ConfidenceBand: "HIGH",
				Context:        sf.Category + ": " + sf.URL,
			})
		}
	}

	// Technology fingerprinting on crawled URLs
	if cfg.TechDetect && len(crawled) > 0 {
		techDetector := recon.NewTechFingerprintWeb(httpClient)
		crawledURLs := make([]string, 0, len(crawled))
		for _, c := range crawled {
			crawledURLs = append(crawledURLs, c.URL)
		}
		for _, sf := range techDetector.Detect(crawledURLs) {
			allFindings = append(allFindings, finding.Finding{
				File:           sf.URL,
				Line:           1,
				RuleName:       sf.Source,
				Severity:       sf.Severity,
				ConfidenceBand: confidenceBandFromScore(sf.Confidence),
				Context:        fmt.Sprintf("%s: %s (confidence=%d)", sf.Category, sf.URL, sf.Confidence),
				Confidence:     sf.Confidence,
			})
		}
	}

	// WAF/CDN detection on crawled URLs
	if cfg.TechDetect && len(crawled) > 0 {
		wafDetector := recon.NewWAFDetector(httpClient)
		crawledURLs := make([]string, 0, len(crawled))
		for _, c := range crawled {
			crawledURLs = append(crawledURLs, c.URL)
		}
		for _, sf := range wafDetector.Detect(crawledURLs) {
			allFindings = append(allFindings, finding.Finding{
				File:     sf.URL,
				Line:     1,
				RuleName: sf.Source,
				Severity: sf.Severity,
				Context:  sf.Category + ": " + sf.URL,
			})
		}
	}

	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
	}
	if cfg.DowngradeFP {
		allFindings = DowngradeFP(allFindings)
	}

	if cfg.CacheDB != "" {
		if cache, err := correlator.OpenCache(cfg.CacheDB); err == nil {
			for i := range allFindings {
				fp := correlator.Fingerprint(allFindings[i].RuleName, allFindings[i].Secret, allFindings[i].File)
				if isNew, _ := cache.RecordWithMeta(fp, allFindings[i].RuleName, allFindings[i].Secret, allFindings[i].File); isNew {
					allFindings[i].IsNew = true
				}
			}
			if cfg.Adaptive && cfg.AdaptiveWeights != nil {
				for i := range allFindings {
					filePattern := adaptive.ExtractFilePattern(allFindings[i].File)
					w := cfg.AdaptiveWeights.Get(allFindings[i].RuleName, filePattern)
					if w != nil {
						allFindings[i].AdaptiveModifier = int(w.Modifier)
						allFindings[i].LearningTier = w.Tier.Label()
					}
				}
			}
			cache.Close()
		}
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

func checkEntropyToken(tok string, thresholds map[string]float64) (bool, float64) {
	if !entropy.IsEntropyTokenMatch(tok) {
		return false, 0
	}
	if len(thresholds) == 0 {
		return true, entropy.Shannon(tok)
	}
	a := entropy.DetectAlphabet(tok)
	alphaName := a.String()
	if override, ok := thresholds[alphaName]; ok {
		e := entropy.EntropyByAlphabet(tok, a)
		return e >= override, e
	}
	return true, entropy.Shannon(tok)
}

func confidenceBandFromScore(score int) string {
	switch {
	case score >= 95:
		return "CRITICAL"
	case score >= 80:
		return "HIGH"
	case score >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// FilterNewOnly returns only findings marked as new (IsNew == true).
func FilterNewOnly(findings []finding.Finding) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		if f.IsNew {
			result = append(result, f)
		}
	}
	return result
}

func contextLabel(tagPrefix string) string {
	switch tagPrefix {
	case "archive_":
		return "archive: "
	case "binary_":
		return "binary: "
	default:
		return "gzip decoded: "
	}
}
