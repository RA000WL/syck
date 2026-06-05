package decoder

import (
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

const MaxRecursionDepth = 3

func DecodeAndRescan(
	line string,
	path string,
	lineno int,
	rs *rules.RuleSet,
	minSev finding.Severity,
	flags Flags,
) []finding.Finding {
	var findings []finding.Finding
	decoders := activeDecoders(flags)
	recursiveDecode(line, path, lineno, rs, minSev, &findings, 0, MaxRecursionDepth, decoders)
	return findings
}

func recursiveDecode(
	text string,
	path string,
	lineno int,
	rs *rules.RuleSet,
	minSev finding.Severity,
	findings *[]finding.Finding,
	depth int,
	maxDepth int,
	decoders []decoderEntry,
) {
	if depth >= maxDepth {
		return
	}

	for _, dec := range decoders {
		results := dec.Decode(text)
		for _, res := range results {
			scanDecoded(res.Text, path, lineno, res.SourceTag, rs, minSev, findings)
			recursiveDecode(res.Text, path, lineno, rs, minSev, findings, depth+1, maxDepth, decoders)
		}
	}
}

func scanDecoded(
	decodedText string,
	path string,
	lineno int,
	sourceTag string,
	rs *rules.RuleSet,
	minSev finding.Severity,
	findings *[]finding.Finding,
) {
	if len(decodedText) > 200 {
		decodedText = decodedText[:200]
	}
	context := sourceTag + " decoded: " + decodedText

	for _, rule := range rs.Rules {
		sev := finding.ParseSeverity(rule.Severity)
		if sev < minSev {
			continue
		}
		if rule.Compiled() == nil {
			continue
		}
		matches := rule.MatchAll(decodedText)
		for _, m := range matches {
			var secret string
			if m[1] <= len(decodedText) {
				secret = decodedText[m[0]:m[1]]
			} else {
				secret = decodedText[m[0]:]
			}

			e := entropy.Shannon(secret)
			if e < 2.0 {
				continue
			}

			*findings = append(*findings, finding.Finding{
				File:     path,
				Line:     lineno,
				Column:   0,
				RuleName: sourceTag + "_" + rule.Name,
				Severity: sev,
				Secret:   secret,
				Context:  context,
				Entropy:  e,
			})
		}
	}
}

func TryGzipDecompress(data []byte) ([]byte, bool) {
	readers := []func([]byte) (io.ReadCloser, error){
		func(b []byte) (io.ReadCloser, error) { return gzip.NewReader(strings.NewReader(string(b))) },
		func(b []byte) (io.ReadCloser, error) { return zlib.NewReader(strings.NewReader(string(b))) },
	}

	for _, mkReader := range readers {
		r, err := mkReader(data)
		if err != nil {
			continue
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err == nil && len(out) > 0 {
			return out, true
		}
	}

	return nil, false
}

func DecodeFileContent(raw []byte) (string, bool) {
	decompressed, ok := TryGzipDecompress(raw)
	if !ok {
		return "", false
	}
	return string(decompressed), true
}
