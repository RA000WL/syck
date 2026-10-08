package scanner

import (
	"strings"

	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

const maxMultiLineWindow = 100

type MultiLineScanner struct {
	rs  *rules.RuleSet
	min finding.Severity
}

func NewMultiLineScanner(rs *rules.RuleSet, min finding.Severity) *MultiLineScanner {
	return &MultiLineScanner{rs: rs, min: min}
}

func (s *MultiLineScanner) ScanMultiLine(lines []string, path string, startLine int) []finding.Finding {
	if len(lines) < 2 {
		return nil
	}
	content := strings.Join(lines, "\n")
	var findings []finding.Finding
	for _, rule := range s.rs.Rules {
		if !rule.MultiLine || rule.Compiled() == nil {
			continue
		}
		sev := rule.SeverityInt
		if sev < s.min {
			continue
		}
		matches := rule.MatchAll(content)
		for _, m := range matches {
			end := m[1]
			if end > len(content) {
				end = len(content)
			}
			secret := content[m[0]:end]

			// Filters in helpers.go's order (helpers.go:529-564): context
			// first because it needs the text, then secret extraction, then the
			// entropy floor, then the three IsFalsePositive* filters.
			//
			// RequiresContext is a no-op for today's ruleset and is here for
			// parity, not effect: none of the 9 multi_line rules in
			// internal/rules/builtin.yaml sets requires_context (and none sets
			// entropy_threshold, so the floor below is the global
			// decoder.RuleEntropyFloor(0) = 2.0). A future multi_line rule that
			// sets it starts being filtered here with no further change. The
			// context text is the whole window, matching decoded path's choice
			// of the text it matches against (decoder/pipeline.go:160-170)
			// rather than the per-line path's single line.
			if rule.RequiresContext && !lineHasContextKeyword(content, rule.ContextKeywords) {
				continue
			}

			e := entropy.Shannon(secret)
			if e < decoder.RuleEntropyFloor(rule.EntropyThreshold) {
				continue
			}
			if entropy.IsFalsePositiveSecret(secret) {
				continue
			}
			// IsFalsePositiveToken is deliberately NOT applied here, the same
			// carve-out Batch 8 made on the decoded path
			// (internal/decoder/pipeline.go:190-208); no per-rule
			// !rule.MultiLine guard is needed because this loop skips every
			// non-multi_line rule on line 28. Its design domain is
			// single-line token-shaped spans, and its hyphen heuristic
			// (>= 3 hyphens and len > 20, aimed at feature-flag names) cannot
			// tell a full PEM block from a flag: a PEM block is nothing but
			// hyphens and base64. Measured on the fixture in
			// multiline_filter_test.go, every fabricated PEM/public-key block
			// here trips it (rsa 5.542, ec 3.952, openssh 4.640, pgp 4.082,
			// public 4.496 — all well clear of the floor), so applying Token
			// on the one path whose multi_line rules exist to report whole
			// blocks would suppress the CRITICAL private-key rules on a
			// default-on path (--multiline defaults true;
			// internal/lsp/server.go forces it on).
			//
			// IsFalsePositiveEmail is applied and is likewise a no-op in
			// practice — no multi_line rule matches email-shaped text, so
			// nothing here can be an opengraph-image@2x.png false positive. It
			// stays so the block reads in the plain path's order.
			if entropy.IsFalsePositiveEmail(secret) {
				continue
			}

			findings = append(findings, finding.Finding{
				File: path, Line: startLine, Column: m[0],
				RuleName: rule.Name + "_multiline", Severity: sev,
				Secret: secret, Context: finding.TruncateContext(content),
				Entropy: e,
			})
		}
	}
	return findings
}
