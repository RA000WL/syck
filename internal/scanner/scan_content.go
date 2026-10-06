package scanner

import (
	"fmt"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/jsanalysis"
	"github.com/RA000WL/syck/internal/json_scanner"
	"github.com/RA000WL/syck/internal/jsrecon"
	"os"
	"path/filepath"
	"strings"
)

func ScanContent(content string, path string, cfg Config) []finding.Finding {
	var findings []finding.Finding
	gzipScanned := make(map[string]bool)
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode

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

	// V1.3: Enhanced JS/source analysis
	ext := strings.ToLower(filepath.Ext(path))
	if (ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs") && content != "" {
		jsResult := jsanalysis.AnalyzeJS(content, path)
		for _, secret := range jsResult.Secrets {
			severity := finding.SeverityMedium
			if secret.Type == "config_secret" || secret.Type == "base64" {
				severity = finding.SeverityHigh
			}
			findings = append(findings, finding.Finding{
				File:     path,
				Line:     secret.Line,
				RuleName: "js_secret_" + secret.Type,
				Severity: severity,
				Secret:   secret.Value,
				Context:  finding.Truncate(secret.Context),
			})
		}
	}

	return findings
}

func scanContent(content string, path string, cfg Config, tagPrefix string,
	skipSecrets map[string]bool, hasDecoders bool) []finding.Finding {
	var findings []finding.Finding

	if cfg.StripComments {
		content = StripLineComments(content)
	}
	lines := strings.Split(content, "\n")

	// Prepare decoders
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

	// Prepare multi-line scanner
	var mlScanner *MultiLineScanner
	if cfg.MultiLine {
		mlScanner = NewMultiLineScanner(cfg.Rules, cfg.MinSeverity)
	}
	mlSeen := map[string]bool{}

	// Scan each line
	for lineNum, line := range lines {
		lineNum++

		// Skip long lines
		if cfg.MaxScanLineLen > 0 && len(line) > cfg.MaxScanLineLen {
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] skipping long line (%d bytes) in %s:%d\n",
					len(line), path, lineNum)
			}
			continue
		}

		// Get context
		ctxBefore, ctxAfter := getLineContext(lines, lineNum)

		// Regex rule matching
		lineFindings := scanLineForRegexRules(line, lineNum, path, cfg, tagPrefix, skipSecrets)
		findings = append(findings, lineFindings...)

		// Multi-line pattern matching
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

		// Entropy token scan
		entropyFindings := scanLineForEntropyTokens(line, lineNum, path, cfg, tagPrefix, skipSecrets, ctxBefore, ctxAfter)
		lineFindings = append(lineFindings, entropyFindings...)
		findings = append(findings, entropyFindings...)

		// Contextual secrets
		ctxFindings := scanLineForContextualSecrets(line, lineNum, path)
		lineFindings = append(lineFindings, ctxFindings...)
		findings = append(findings, ctxFindings...)

		// Build decoder skip list from secrets already found on this line
		lineSkipSecrets := skipSecrets
		if hasDecoders && len(lineFindings) > 0 {
			if lineSkipSecrets == nil {
				lineSkipSecrets = make(map[string]bool, len(lineFindings))
			} else {
				lineSkipSecrets = make(map[string]bool, len(skipSecrets)+len(lineFindings))
				for k, v := range skipSecrets {
					lineSkipSecrets[k] = v
				}
			}
			for _, f := range lineFindings {
				key := f.Secret
				if len(key) > 60 {
					key = key[:60]
				}
				lineSkipSecrets[key] = true
			}
		}

		// Decoded content scan
		if hasDecoders {
			findings = append(findings, scanLineForDecodedContent(line, lineNum, path, cfg, tagPrefix, lineSkipSecrets, activeDec)...)
		}

		// Auth header detection
		if cfg.DetectAuthHeaders {
			findings = append(findings, scanLineForAuthHeaders(line, lineNum, path)...)
		}

		// URL secret extraction
		findings = append(findings, scanLineForURLSecrets(line, lineNum, path)...)

		// Expired JWT detection
		findings = append(findings, ScanExpiredJWTs(line, lineNum, path)...)
	}

	// Source technology fingerprinting
	if cfg.TechDetect {
		findings = append(findings, DetectSourceTech(content, path)...)
	}

	return findings
}
