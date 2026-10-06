package scanner

import (
	"fmt"
	"github.com/RA000WL/syck/internal/crawler"
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

func ScanBinaryFile(path string, cfg Config) ([]finding.Finding, error) {
	strs, err := ExtractBinaryStrings(path)
	if err != nil || len(strs) == 0 {
		return nil, err
	}
	var findings []finding.Finding
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode
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
			// Size gate: never slurp an oversized archive into memory.
			if cfg.MaxFileSize > 0 && info.Size() > cfg.MaxFileSize {
				if cfg.Debug {
					fmt.Fprintf(os.Stderr, "[debug] skip archive (size %d > max %d): %s\n", info.Size(), cfg.MaxFileSize, path)
				}
				return nil, nil
			}
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
			hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode
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
	hasDecoders := cfg.DecodeBase64 || cfg.DecodeHex || cfg.DecodeUnicode || cfg.DecodeURL || cfg.DecodeBase64URL || cfg.DecodeJWT || cfg.DecodeDoubleBase64 || cfg.DecodeCharCode

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

	// V1.3: Enhanced JS/source analysis for hidden exposures
	ext := strings.ToLower(filepath.Ext(path))
	if (ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs") && content != "" {
		jsResult := jsanalysis.AnalyzeJS(content, path)

		// Emit findings for discovered secrets
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

		// Emit findings for internal URLs (potential SSRF)
		for _, internalURL := range jsResult.InternalURLs {
			findings = append(findings, finding.Finding{
				File:     path,
				Line:     1,
				RuleName: "internal_url",
				Severity: finding.SeverityMedium,
				Secret:   internalURL,
				Context:  fmt.Sprintf("internal/hidden URL found in %s", filepath.Base(path)),
			})
		}

		// Emit findings for debug artifacts
		for _, debug := range jsResult.DebugArtifacts {
			findings = append(findings, finding.Finding{
				File:     path,
				Line:     1,
				RuleName: "debug_artifact",
				Severity: finding.SeverityLow,
				Secret:   debug,
				Context:  fmt.Sprintf("debug/development artifact in %s", filepath.Base(path)),
			})
		}

		// Emit findings for sensitive files
		for _, sf := range jsResult.SensitiveFiles {
			findings = append(findings, finding.Finding{
				File:     path,
				Line:     1,
				RuleName: "sensitive_file_ref",
				Severity: finding.SeverityMedium,
				Secret:   sf,
				Context:  fmt.Sprintf("sensitive file reference in %s", filepath.Base(path)),
			})
		}

		// Emit findings for leaked comments
		for _, comment := range jsResult.LeakedComments {
			if strings.Contains(comment, "api") || strings.Contains(comment, "key") ||
				strings.Contains(comment, "token") || strings.Contains(comment, "secret") ||
				strings.Contains(comment, "internal") {
				findings = append(findings, finding.Finding{
					File:     path,
					Line:     1,
					RuleName: "comment_leak",
					Severity: finding.SeverityMedium,
					Secret:   comment,
					Context:  fmt.Sprintf("URL found in comment in %s", filepath.Base(path)),
				})
			}
		}
	}

	return findings, nil
}
