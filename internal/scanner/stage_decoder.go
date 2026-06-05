package scanner

import (
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type DecoderFlags struct {
	Base64  bool
	Hex     bool
	Unicode bool
	URL     bool
}

type DecoderStage struct {
	rs    *rules.RuleSet
	min   finding.Severity
	flags DecoderFlags
}

func NewDecoderStage(rs *rules.RuleSet, min finding.Severity, flags DecoderFlags) *DecoderStage {
	return &DecoderStage{rs: rs, min: min, flags: flags}
}

func (s *DecoderStage) Process(line, path string, lineno int) []finding.Finding {
	df := decoder.Flags{Base64: s.flags.Base64, Hex: s.flags.Hex, Unicode: s.flags.Unicode, URL: s.flags.URL}
	return decoder.DecodeAndRescan(line, path, lineno, s.rs, s.min, df)
}
