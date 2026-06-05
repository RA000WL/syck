package scanner

import (
	"strings"

	"github.com/RA000WL/syck/internal/endpoints"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/jsrecon"
	"github.com/RA000WL/syck/internal/recon"
	"github.com/RA000WL/syck/internal/rules"
)

type CollectorStage struct {
	jsRecon  bool
	reconReg *recon.Registry
	rs       *rules.RuleSet
	minSev   finding.Severity
}

func NewCollectorStage(cfg Config) *CollectorStage {
	s := &CollectorStage{
		jsRecon:  cfg.JSReconstruct,
		reconReg: recon.NewRegistry(),
		rs:       cfg.Rules,
		minSev:   cfg.MinSeverity,
	}

	s.reconReg.Register(recon.GraphQLDetector{})
	s.reconReg.Register(recon.SwaggerDetector{})
	s.reconReg.Register(recon.AdminDetector{})
	s.reconReg.Register(recon.DebugDetector{})
	s.reconReg.Register(recon.MetricsDetector{})
	s.reconReg.Register(recon.InternalDetector{})
	s.reconReg.Register(recon.StagingDetector{})
	s.reconReg.Register(recon.StorageDetector{})
	s.reconReg.Register(recon.AuthDetector{})

	return s
}

func (s *CollectorStage) Process(content, path string) []finding.Finding {
	var findings []finding.Finding

	isJS := false
	lower := strings.ToLower(path)
	for _, ext := range []string{".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs"} {
		if strings.HasSuffix(lower, ext) {
			isJS = true
			break
		}
	}

	extracted := endpoints.ExtractEndpoints(path, content)
	urls := make([]string, len(extracted))
	urlByEndpoint := make(map[string]endpoints.Endpoint)
	for i, ep := range extracted {
		urls[i] = ep.Endpoint
		urlByEndpoint[ep.Endpoint] = ep
	}

	if isJS && s.jsRecon {
		jsRequests := jsrecon.Analyze(content, path)
		for _, req := range jsRequests {
			if req.Endpoint != "" {
				urls = append(urls, req.Endpoint)
			}
		}
	}

	surfaceFindings := s.reconReg.Detect(urls)

	for _, sf := range surfaceFindings {
		f := finding.Finding{
			File:       path,
			RuleName:   "attack_surface_" + sf.Category,
			Severity:   sf.Severity,
			Confidence: "HIGH",
			Context:    sf.Category + ": " + sf.URL,
		}
		if ep, ok := urlByEndpoint[sf.URL]; ok {
			f.Line = ep.Line
			f.Context = ep.Context
		}
		if f.Severity >= s.minSev {
			findings = append(findings, f)
		}
	}

	return findings
}
