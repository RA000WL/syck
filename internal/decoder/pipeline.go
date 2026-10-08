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
	decoders := PrecomputeDecoders(flags)
	if len(decoders) == 0 {
		return nil
	}
	var findings []finding.Finding
	recursiveDecode(line, path, lineno, rs, minSev, &findings, 0, MaxRecursionDepth, decoders, make(map[string]int))
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
	recursiveDecode(line, path, lineno, rs, minSev, &findings, 0, MaxRecursionDepth, decoders, make(map[string]int))
	return findings
}

// recursiveDecode decodes text with each active decoder, scans every decoded
// result, and recurses into it.
//
// visited is a per-line set of already-expanded decoded texts keyed by the
// depth at which each was first expanded. A repeat is skipped only when it is
// reached again at the same or a deeper depth — its remaining decode budget
// is then no larger than the first visit's — so a text re-reached at a
// shallower depth still gets its full budget. This bounds fan-out (the same
// intermediate text is not re-expanded for every path that produces it)
// without losing reachable secrets.
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
	visited map[string]int,
) {
	if depth >= maxDepth {
		return
	}

	for _, dec := range decoders {
		results := dec(text)
		for _, res := range results {
			if prev, seen := visited[res.Text]; seen && prev <= depth {
				continue
			}
			visited[res.Text] = depth
			scanDecoded(res.Text, path, lineno, res.SourceTag, rs, minSev, findings)
			recursiveDecode(res.Text, path, lineno, rs, minSev, findings, depth+1, maxDepth, decoders, visited)
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

// RuleEntropyFloor returns the minimum Shannon entropy a match must reach:
// the rule's own EntropyThreshold when configured (> 0), else the global 2.0 floor.
// Exported from decoder so both the decoded-content path here and the regex
// paths in scanner share one definition (scanner cannot be imported by
// decoder — scanner imports decoder — so the helper cannot live there).
func RuleEntropyFloor(th float64) float64 {
	if th > 0 {
		return th
	}
	return 2.0
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
	// Scan the full chunk: scanDecoded already bounds the work by chunking
	// at scanChunkSize, and truncating here silently dropped secrets past
	// the cut point.
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
			// Context-check text is the decoded chunk — this path's "line". The
			// source line is the encoded blob, whose keywords are whatever the
			// caller happened to write beside it, and the secret is usually not
			// on that line at all in any recognizable form; the decoded chunk is
			// both the text the rules are matched against and the text a human
			// sees once the blob is decoded. The plain path checks the same text
			// it matches rules against (helpers.go:529), so this keeps the two
			// paths comparable rather than making this one stricter.
			if rule.RequiresContext && !hasContextKeyword(decodedText, rule.ContextKeywords) {
				continue
			}
			var secret string
			if m[1] <= len(decodedText) {
				secret = decodedText[m[0]:m[1]]
			} else {
				secret = decodedText[m[0]:]
			}

			e := entropy.Shannon(secret)
			if e < RuleEntropyFloor(rule.EntropyThreshold) {
				continue
			}
			if entropy.IsFalsePositiveSecret(secret) {
				continue
			}
			// Token and Email were already applied on this path before this
			// batch; they stay exactly where they were, so each filter runs once
			// and the whole block reads in the plain path's order
			// (helpers.go:555-563).
			//
			// The Token filter is skipped for multi_line rules. Its design
			// domain is single-line token-shaped spans, and its hyphen
			// heuristic (>= 3 hyphens and len > 20, aimed at feature-flag names)
			// has no way to tell a full PEM block from a feature flag: a PEM
			// block is nothing but hyphens and base64. The decoder iterates
			// every rule, the multi_line ones included, and those rules exist so
			// that base64-decoded content can be scanned at all — so applying
			// Token here suppressed the CRITICAL rsa/ec/openssh/pgp private-key
			// rules on the one path whose whole purpose is finding them.
			// Internal/scanner/multiline.go, which applies no filters, still
			// reports those blocks from plain files, so this was a decoded-path
			// loss rather than a policy.
			//
			// Secret and Email are NOT exempted: they are span-shape-agnostic
			// (placeholders and email addresses are false positives at any
			// length and arity).
			if !rule.MultiLine && entropy.IsFalsePositiveToken(secret) {
				continue
			}
			if entropy.IsFalsePositiveEmail(secret) {
				continue
			}

			isDuplicate := false
			for _, f := range *findings {
				if f.Secret == secret {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
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

// hasContextKeyword is a copy of scanner.lineHasContextKeyword (stage_rule.go:44),
// which this package cannot call: internal/scanner imports internal/decoder, so
// importing it back would be an import cycle. Same case-insensitive substring
// test over the rule's own context_keywords.
func hasContextKeyword(text string, keywords []string) bool {
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// maxDecompressed caps gzip/zlib output so a small hostile input cannot
// expand into an unbounded allocation (decompression bomb).
const maxDecompressed = 5 << 20

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
		// Read one byte past the cap so oversized streams are still detectable.
		out, err := io.ReadAll(io.LimitReader(r, int64(maxDecompressed)+1))
		if err == nil && len(out) > 0 {
			if len(out) > maxDecompressed {
				out = out[:maxDecompressed]
			}
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
