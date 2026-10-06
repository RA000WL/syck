package scanner

import (
	"bufio"
	"fmt"
	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"os"
	"strings"
)

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
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode
	df := decoder.Flags{
		Base64:       cfg.DecodeBase64,
		Hex:          cfg.DecodeHex,
		Unicode:      cfg.DecodeUnicode,
		URL:          cfg.DecodeURL,
		Base64URL:    cfg.DecodeBase64URL,
		JWT:          cfg.DecodeJWT,
		DoubleBase64: cfg.DecodeDoubleBase64,
		Gzip:         cfg.DecodeGzip,
		CharCode:     cfg.DecodeCharCode || cfg.DecodeHex || cfg.DecodeUnicode,
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

		if cfg.Debug && lineNum%10000 == 0 {
			fmt.Fprintf(os.Stderr, "\r[debug] streaming %s: %d lines scanned...", path, lineNum)
		}

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

		var lineFindings []finding.Finding

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
				if e < decoder.RuleEntropyFloor(rule.EntropyThreshold) {
					continue
				}
				if entropy.IsFalsePositiveSecret(secret) {
					continue
				}
				if entropy.IsFalsePositiveToken(secret) {
					continue
				}
				if entropy.IsFalsePositiveEmail(secret) {
					continue
				}

				f := finding.Finding{
					File:            path,
					Line:            lineNum,
					Column:          m[0],
					RuleName:        rule.Name,
					Severity:        sev,
					Secret:          secret,
					Context:         finding.Truncate(strings.TrimSpace(line)),
					ContextBefore:   finding.Truncate(ctxBefore),
					Entropy:         e,
					Confidence:      confidence.PtsRegex,
					ConfidenceBand:  confidence.Band(confidence.PtsRegex),
					DetectionMethod: "regex",
				}
				lineFindings = append(lineFindings, f)
				findings = append(findings, f)
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
				if entropy.IsFalsePositiveToken(tok) {
					continue
				}
				col := strings.Index(line, tok)
				if col < 0 {
					col = 0
				}
				f := finding.Finding{
					File:            path,
					Line:            lineNum,
					Column:          col,
					RuleName:        "high_entropy_token",
					Severity:        finding.SeverityMedium,
					Secret:          tok,
					Context:         finding.Truncate(strings.TrimSpace(line)),
					ContextBefore:   finding.Truncate(ctxBefore),
					Entropy:         tokEntropy,
					Confidence:      confidence.PtsEntropy + confidence.PtsContext,
					ConfidenceBand:  confidence.Band(confidence.PtsEntropy + confidence.PtsContext),
					DetectionMethod: "entropy+context",
				}
				lineFindings = append(lineFindings, f)
				findings = append(findings, f)
			}
		}

		for _, cs := range entropy.ExtractContextualSecrets(line, 4.5) {
			if entropy.IsMediaToken(cs.Token) {
				continue
			}
			if entropy.IsFalsePositiveToken(cs.Token) {
				continue
			}
			f := finding.Finding{
				File:            path,
				Line:            lineNum,
				Column:          strings.Index(line, cs.Token),
				RuleName:        "contextual_entropy_secret",
				Severity:        finding.SeverityHigh,
				Secret:          cs.Token,
				Context:         finding.Truncate(strings.TrimSpace(line)),
				Entropy:         cs.Entropy,
				Confidence:      confidence.PtsEntropy + confidence.PtsContext,
				ConfidenceBand:  confidence.Band(confidence.PtsEntropy + confidence.PtsContext),
				DetectionMethod: "entropy+context",
			}
			lineFindings = append(lineFindings, f)
			findings = append(findings, f)
		}

		if hasDecoders && len(lineFindings) > 0 {
			lineSkipSecrets := make(map[string]bool, len(lineFindings))
			for _, lf := range lineFindings {
				key := lf.Secret
				if len(key) > 60 {
					key = key[:60]
				}
				lineSkipSecrets[key] = true
			}
			decodedFindings := decoder.DecodeAndRescanWithDecoders(line, path, lineNum,
				cfg.Rules, cfg.MinSeverity, activeDec)
			for _, df := range decodedFindings {
				key := df.Secret
				if len(key) > 60 {
					key = key[:60]
				}
				if !lineSkipSecrets[key] {
					findings = append(findings, markDecodedFindings([]finding.Finding{df})...)
				}
			}
		} else if hasDecoders {
			findings = append(findings, markDecodedFindings(decoder.DecodeAndRescanWithDecoders(line, path, lineNum,
				cfg.Rules, cfg.MinSeverity, activeDec))...)
		}

		urlFindings := ExtractURLSecrets(line, path, lineNum)
		findings = append(findings, urlFindings...)

		jwtFindings := ScanExpiredJWTs(line, lineNum, path)
		findings = append(findings, jwtFindings...)

		prevLine = line
	}

	if cfg.Debug && lineNum > 10000 {
		fmt.Fprintf(os.Stderr, "\r[debug] streaming %s: %d lines scanned done.\n", path, lineNum)
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] %s: line exceeds scanner buffer, falling back to full read\n", path)
			}
			return scanFileFallback(path, cfg)
		}
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

func scanFileFallback(path string, cfg Config) ([]finding.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: fallback read: %w", path, err)
	}

	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode
	content := string(raw)

	var findings []finding.Finding

	if cfg.DecodeGzip && len(raw) > 64 {
		if decompressed, ok := decoder.DecodeFileContent(raw); ok {
			gzipFindings := scanContent(string(decompressed), path, cfg, "gzip_", nil, hasDecoders)
			findings = append(findings, gzipFindings...)
		}
	}

	findings = append(findings, scanContent(content, path, cfg, "", nil, hasDecoders)...)

	if cfg.Endpoints {
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
