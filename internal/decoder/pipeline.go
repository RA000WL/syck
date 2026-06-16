package decoder

import (
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"io"
	"regexp"
	"strings"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

const MaxRecursionDepth = 3

const (
	scanChunkSize = 1024
	scanOverlap   = 128
)

func DecodeAndRescan(
	line string,
	path string,
	lineno int,
	rs *rules.RuleSet,
	minSev finding.Severity,
	flags Flags,
) []finding.Finding {
	decoders := activeDecoders(flags)
	if len(decoders) == 0 {
		return nil
	}
	var findings []finding.Finding
	recursiveDecode(line, path, lineno, rs, minSev, &findings, 0, MaxRecursionDepth, decoders)
	return findings
}

// DecodeAndRescanWithDecoders is like DecodeAndRescan but uses a pre-computed
// decoder list. Use PrecomputeDecoders to get the list once per scan config,
// then call this per line to avoid re-computing the decoder list thousands of times.
func DecodeAndRescanWithDecoders(
	line string,
	path string,
	lineno int,
	rs *rules.RuleSet,
	minSev finding.Severity,
	decoders []Decoder,
) []finding.Finding {
	if len(decoders) == 0 {
		return nil
	}
	var findings []finding.Finding
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
	decoders []Decoder,
) {
	if depth >= maxDepth {
		return
	}

	for _, dec := range decoders {
		results := dec(text)
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
	if len(decodedText) <= scanChunkSize {
		scanDecodedChunk(decodedText, path, lineno, sourceTag, rs, minSev, findings)
		return
	}
	for i := 0; i < len(decodedText); i += scanChunkSize - scanOverlap {
		end := i + scanChunkSize
		if end > len(decodedText) {
			end = len(decodedText)
		}
		chunk := decodedText[i:end]
		scanDecodedChunk(chunk, path, lineno, sourceTag, rs, minSev, findings)
		if end == len(decodedText) {
			break
		}
	}
}

func scanDecodedChunk(
	decodedText string,
	path string,
	lineno int,
	sourceTag string,
	rs *rules.RuleSet,
	minSev finding.Severity,
	findings *[]finding.Finding,
) {
	if len(decodedText) > 500 {
		decodedText = decodedText[:500]
	}
	context := sourceTag + " decoded: " + decodedText

	for _, rule := range rs.Rules {
		sev := rule.SeverityInt
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

var b64GzipRE = regexp.MustCompile(`\b[A-Za-z0-9+/]{64,}={0,2}\b`)

func tryGzipInline(line string) []DecodeResult {
	var results []DecodeResult
	for _, m := range b64GzipRE.FindAllString(line, -1) {
		decoded, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			decoded, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(m)
			if err != nil {
				continue
			}
		}
		if decompressed, ok := TryGzipDecompress(decoded); ok {
			results = append(results, DecodeResult{SourceTag: "gzip", Text: string(decompressed)})
		}
	}
	return results
}

func DecodeFileContent(raw []byte) (string, bool) {
	decompressed, ok := TryGzipDecompress(raw)
	if !ok {
		return "", false
	}
	return string(decompressed), true
}
