package scanner

import (
	"strings"

	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
)

type Pipeline struct {
	Rule        *RuleStage
	Decoder     *DecoderStage
	Entropy     *EntropyStage
	Correlation *CorrelationStage
	Verifier    *VerifierStage
	Confidence  *ConfidenceStage
	Reporter    *ReporterStage
}

func NewPipeline(cfg Config) *Pipeline {
	return &Pipeline{
		Rule:        NewRuleStage(cfg.Rules, cfg.MinSeverity),
		Decoder:     NewDecoderStage(cfg.Rules, cfg.MinSeverity, DecoderFlags{Base64: cfg.DecodeBase64, Hex: cfg.DecodeHex, Unicode: cfg.DecodeUnicode, URL: cfg.DecodeURL}),
		Entropy:     NewEntropyStage(),
		Correlation: NewCorrelationStage(correlation.NewCorrelator()),
		Verifier:    NewVerifierStage(),
		Confidence:  NewConfidenceStage(),
		Reporter:    NewReporterStage(!cfg.NoDedup, cfg.DowngradeFP),
	}
}

func (p *Pipeline) ScanString(content, path string) ([]finding.Finding, error) {
	var all []finding.Finding
	for lineno, line := range strings.Split(content, "\n") {
		all = append(all, p.Rule.Process(line, path, lineno+1)...)
		all = append(all, p.Decoder.Process(line, path, lineno+1)...)
		all = append(all, p.Entropy.Process(line, path, lineno+1)...)
	}
	all = p.Correlation.Process(all)
	all = p.Verifier.Process(all)
	all = p.Confidence.Process(all)
	all = p.Reporter.Process(all)
	return all, nil
}
