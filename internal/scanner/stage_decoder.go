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
	Gzip    bool
}

type DecoderStage struct {
	rs       *rules.RuleSet
	min      finding.Severity
	flags    DecoderFlags
	decoders []decoder.Decoder
}

func NewDecoderStage(rs *rules.RuleSet, min finding.Severity, flags DecoderFlags) *DecoderStage {
	df := decoder.Flags{Base64: flags.Base64, Hex: flags.Hex, Unicode: flags.Unicode, URL: flags.URL}
	return &DecoderStage{
		rs:       rs,
		min:      min,
		flags:    flags,
		decoders: decoder.PrecomputeDecoders(df),
	}
}

func (s *DecoderStage) Process(line, path string, lineno int) []finding.Finding {
	return decoder.DecodeAndRescanWithDecoders(line, path, lineno, s.rs, s.min, s.decoders)
}
