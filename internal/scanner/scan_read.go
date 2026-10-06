package scanner

import (
	"bufio"
	"fmt"
	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/correlator"
	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/jsrecon"
	"os"
	"strings"
)

func ScanReader(r *os.File, cfg Config) ([]finding.Finding, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, stdinScanBufferBytes)
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
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode
	findings := scanContent(content, "stdin", cfg, "", nil, hasDecoders)

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
			recordFingerprints(cache, findings)
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
