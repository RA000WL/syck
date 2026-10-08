package scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Batch 9 characterization of internal/scanner/multiline.go, the last
// rule-matching path with no filters at all: no entropy floor, no
// IsFalsePositive* filters, no RequiresContext. Every other path (plain lines
// via helpers.go:529-564, the decoded path via decoder/pipeline.go:168-211,
// jsrecon, json_scanner, scan_stream) has them.
//
// The tests below pin current behaviour so the filters added in Task 2 have a
// measurable, non-vacuous effect. Entropy is measured, not asserted from a
// threshold guess: each case logs the Shannon value of the exact span the
// multi_line rule matched, so the floor's effect is visible rather than
// inferred.

// Every key body below is FABRICATED — character soup shaped like a real key,
// not a key. No fixture in this file can authenticate to anything.
const (
	pemRSABody1 = "MIIEabc123DEF456ghi789JKL012mno345PQR678stu901VWX234yzYdEfGhIjKlMn"
	pemRSABody2 = "OpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcDEFfghIjKlMnOpQr"
	pemECBody   = "MHcCAQEEIFakefakefakefakefakefakefakefakefakefakefakefakefakefake"
	pemSSHBody  = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMWZpY2tl"
	pemPGPBody  = "mQINBFakefakefakefakefakefakefakefakefakefakefakefakefakefakefake"
	pubKeyBody  = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfakefakefakefakefake"
)

// multilineCase is one fixture window handed to ScanMultiLine. ScanMultiLine
// returns nil for len(lines) < 2, so every case spans >= 2 lines by necessity.
type multilineCase struct {
	name  string
	lines []string
}

func multilineCases() []multilineCase {
	return []multilineCase{
		{
			// The guard. A full PEM block is nothing but hyphens and base64,
			// which is exactly the shape IsFalsePositiveToken's >= 3 hyphens /
			// len > 20 heuristic was written to reject (feature-flag names).
			name: "pem_rsa_private_key",
			lines: []string{
				"-----BEGIN RSA PRIVATE KEY-----",
				pemRSABody1,
				pemRSABody2,
				"-----END RSA PRIVATE KEY-----",
			},
		},
		{
			name: "pem_ec_private_key",
			lines: []string{
				"-----BEGIN EC PRIVATE KEY-----",
				pemECBody,
				"-----END EC PRIVATE KEY-----",
			},
		},
		{
			name: "pem_openssh_private_key",
			lines: []string{
				"-----BEGIN OPENSSH PRIVATE KEY-----",
				pemSSHBody,
				"-----END OPENSSH PRIVATE KEY-----",
			},
		},
		{
			name: "pem_pgp_private_key",
			lines: []string{
				"-----BEGIN PGP PRIVATE KEY BLOCK-----",
				pemPGPBody,
				"-----END PGP PRIVATE KEY BLOCK-----",
			},
		},
		{
			name: "rsa_public_key",
			lines: []string{
				"-----BEGIN PUBLIC KEY-----",
				pubKeyBody,
				"-----END PUBLIC KEY-----",
			},
		},
		{
			// A realistic kubernetes Secret manifest. The multi_line
			// kubernetes_secret rule only consumes the apiVersion/kind header
			// pair, so the embedded data line is context, not part of the span.
			name: "kubernetes_secret",
			lines: []string{
				"apiVersion: v1",
				"kind: Secret",
				"metadata:",
				"  name: my-secret",
				"type: Opaque",
				"data:",
				"  password: c3VwZXItc2VjcmV0LXZhbHVl",
			},
		},
		{
			// A realistic docker-compose environment block with a
			// real-looking password value — the probable survivor.
			name: "docker_compose_secret",
			lines: []string{
				"services:",
				"  web:",
				"    environment:",
				"      DATABASE_PASSWORD: \"q7Xf9Lm2Zp4Rt8Vw\"",
			},
		},
		{
			// FP-shaped: a value with no entropy at all. The
			// docker_compose_secret rule matches the environment/keyword/value
			// shape regardless of what the value is, so a long run of one
			// letter — padding, a redacted placeholder, a test fixture — matches
			// exactly like a real password. The window is the realistic
			// docker-compose layout, not a trimmed-down one, so the span is the
			// span a real scan produces.
			name: "docker_compose_low_entropy_value",
			lines: []string{
				"services:",
				"  web:",
				"    environment:",
				"      PASSWORD: \"" + strings.Repeat("a", 96) + "\"",
			},
		},
		{
			// Boundary control for the previous case: identical window, same
			// rule, value 24 characters shorter. It clears the floor, which is
			// what makes the previous case's suppression attributable to the
			// value's entropy rather than to the shape.
			name: "docker_compose_low_entropy_boundary",
			lines: []string{
				"services:",
				"  web:",
				"    environment:",
				"      PASSWORD: \"" + strings.Repeat("a", 72) + "\"",
			},
		},
	}
}

// multilineRuleNamesOf renders a findings slice as rule names, so an assertion
// failure shows both sides and any ADDED finding fails the test too (the point
// of asserting the whole slice rather than "contains").
func multilineRuleNamesOf(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleName)
	}
	return out
}

// multilineSpan is one span a multi_line rule consumed, together with the
// measured Shannon entropy and filter verdicts for that exact span.
type multilineSpan struct {
	rule     string
	len      int
	entropy  float64
	fpSecret bool
	fpToken  bool
	fpEmail  bool
}

func (s multilineSpan) String() string {
	floor := decoder.RuleEntropyFloor(0)
	return fmt.Sprintf("rule=%-24s len=%-4d entropy=%6.3f floor(%.1f)_ok=%-5v IsFalsePositiveSecret=%-5v IsFalsePositiveToken=%-5v IsFalsePositiveEmail=%v",
		s.rule, s.len, s.entropy, floor, s.entropy >= floor, s.fpSecret, s.fpToken, s.fpEmail)
}

// multilineSpans returns, per fixture, every span each builtin multi_line rule
// matched, so entropy can be measured on the span the filters will actually
// see. A span here that no filter can reject is itself a characterization
// result.
func multilineSpans(rs *rules.RuleSet) map[string][]multilineSpan {
	out := map[string][]multilineSpan{}
	for _, c := range multilineCases() {
		content := strings.Join(c.lines, "\n")
		for _, rule := range rs.Rules {
			if !rule.MultiLine || rule.Compiled() == nil {
				continue
			}
			for _, m := range rule.MatchAll(content) {
				end := m[1]
				if end > len(content) {
					end = len(content)
				}
				secret := content[m[0]:end]
				out[c.name] = append(out[c.name], multilineSpan{
					rule:     rule.Name,
					len:      len(secret),
					entropy:  entropy.Shannon(secret),
					fpSecret: entropy.IsFalsePositiveSecret(secret),
					fpToken:  entropy.IsFalsePositiveToken(secret),
					fpEmail:  entropy.IsFalsePositiveEmail(secret),
				})
			}
		}
	}
	return out
}

func loadBuiltinRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return rs
}

// scanMultilineCase runs the real builtin multi_line rules over a fixture
// window, the same construction internal/scanner/scan_content.go uses.
func scanMultilineCase(t *testing.T, c multilineCase) []finding.Finding {
	t.Helper()
	return NewMultiLineScanner(loadBuiltinRules(t), finding.SeverityLow).ScanMultiLine(c.lines, "fixture.txt", 1)
}

// TestMultiLineCharacterizeSpans logs the measured filter verdict for every
// span in the corpus. It asserts only what must hold for the corpus to mean
// anything: every case matched at least one rule, the floor's victim is a
// genuine sub-floor span, and every survivor clears the floor (otherwise
// "survivors still report" would be measuring the floor, not the filters).
func TestMultiLineCharacterizeSpans(t *testing.T) {
	spans := multilineSpans(loadBuiltinRules(t))
	for _, c := range multilineCases() {
		got := spans[c.name]
		if len(got) == 0 {
			t.Fatalf("%s: no multi_line rule matched the fixture — corpus is vacuous", c.name)
		}
		for _, s := range got {
			t.Logf("%-34s %s", c.name, s)
		}
	}
	for _, s := range spans["docker_compose_low_entropy_value"] {
		if s.entropy >= 2.0 {
			t.Errorf("low-entropy fixture entropy = %v, want < 2.0 so the floor has something to bite on", s.entropy)
		}
	}
	for _, c := range multilineCases() {
		if c.name == "docker_compose_low_entropy_value" {
			continue
		}
		for _, s := range spans[c.name] {
			if s.entropy < 2.0 {
				t.Errorf("%s: entropy = %v, want >= 2.0 for a survivor", c.name, s.entropy)
			}
		}
	}
}

// TestMultiLinePEMBlockStillReported is Batch 9's keystone guard.
//
// Batch 8 found that IsFalsePositiveToken's hyphen heuristic (>= 3 hyphens and
// len > 20, aimed at feature-flag names) fires on any full PEM block — a block
// is nothing but hyphens and base64 — and suppressed the CRITICAL
// rsa/ec/openssh/pgp private-key rules on the decoded path. This batch adds
// filters to the multi_line path, where those same rules fire, so the guard is
// re-asserted here. Without the Token exemption the worst possible outcome
// follows: private keys silently stop being reported on a default-on path
// (--multiline defaults true and internal/lsp/server.go forces it on).
//
// The test is non-vacuous by construction: it first proves the fixture really
// does trip IsFalsePositiveToken, so a future change to that filter cannot
// make the test pass for the wrong reason.
func TestMultiLinePEMBlockStillReported(t *testing.T) {
	want := map[string]struct {
		rules    []string
		severity finding.Severity
	}{
		"pem_rsa_private_key":     {[]string{"rsa_private_key_multiline"}, finding.SeverityCritical},
		"pem_ec_private_key":      {[]string{"ec_private_key_multiline"}, finding.SeverityCritical},
		"pem_openssh_private_key": {[]string{"openssh_private_key_multiline"}, finding.SeverityCritical},
		"pem_pgp_private_key":     {[]string{"pgp_private_key_multiline"}, finding.SeverityHigh},
		"rsa_public_key":          {[]string{"rsa_public_key_multiline"}, finding.SeverityMedium},
	}
	spans := multilineSpans(loadBuiltinRules(t))
	for _, c := range multilineCases() {
		expected, ok := want[c.name]
		if !ok {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			// Non-vacuity: the span must be one IsFalsePositiveToken rejects.
			tripped := false
			for _, s := range spans[c.name] {
				if s.fpToken {
					tripped = true
					t.Logf("fixture trips IsFalsePositiveToken (entropy %.3f, len %d) — the exemption is load-bearing", s.entropy, s.len)
				}
			}
			if !tripped {
				t.Fatal("fixture no longer trips IsFalsePositiveToken; the PEM guard is vacuous")
			}

			findings := scanMultilineCase(t, c)
			got := multilineRuleNamesOf(findings)
			if strings.Join(got, ",") != strings.Join(expected.rules, ",") {
				t.Fatalf("findings = %v, want %v — PEM block suppressed on the multi_line path", got, expected.rules)
			}
			for _, f := range findings {
				if f.Severity != expected.severity {
					t.Errorf("%s severity = %v, want %v", f.RuleName, f.Severity, expected.severity)
				}
			}
		})
	}
}

// TestMultiLineCharacterizeSurvivors pins the shapes that must survive every
// filter added in Task 2. These are the realistic multi_line matches: a
// kubernetes Secret header and a docker-compose environment block.
func TestMultiLineCharacterizeSurvivors(t *testing.T) {
	want := map[string][]string{
		"kubernetes_secret":                   {"kubernetes_secret_multiline"},
		"docker_compose_secret":               {"docker_compose_secret_multiline"},
		"docker_compose_low_entropy_boundary": {"docker_compose_secret_multiline"},
	}
	for _, c := range multilineCases() {
		expected, ok := want[c.name]
		if !ok {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			got := multilineRuleNamesOf(scanMultilineCase(t, c))
			if strings.Join(got, ",") != strings.Join(expected, ",") {
				t.Fatalf("findings = %v, want %v", got, expected)
			}
		})
	}
}

// TestMultiLineLowEntropySpanSuppressedByFloor is the batch's measurable win,
// and the only filter that bites on the builtin multi_line rules. The
// docker_compose_secret rule matches on shape, so a run of one repeated letter
// was reported with the same HIGH severity as a real password; the entropy
// floor removes it (measured span entropy 1.756 vs the 2.0 floor).
//
// The paired boundary case — same window, same rule, a 24-character shorter
// run — is asserted to still report, so the suppression is attributable to the
// value's entropy and not to the shape. Measured on the realistic window: 48
// a's → 2.500, 64 → 2.187, 72 → 2.059 (all reported), 80 → 1.946, 96 → 1.756,
// 128 → 1.474, 200 → 1.093 (all suppressed).
//
// Before the filters both cases reported exactly one finding — the git-history
// version of this test pinned that behaviour first.
func TestMultiLineLowEntropySpanSuppressedByFloor(t *testing.T) {
	const (
		suppressed = "docker_compose_low_entropy_value"
		boundary   = "docker_compose_low_entropy_boundary"
	)
	for _, c := range multilineCases() {
		switch c.name {
		case suppressed:
			got := scanMultilineCase(t, c)
			if len(got) != 0 {
				t.Fatalf("findings = %v, want none — sub-floor span should have been dropped", multilineRuleNamesOf(got))
			}
		case boundary:
			got := multilineRuleNamesOf(scanMultilineCase(t, c))
			if len(got) != 1 {
				t.Fatalf("findings = %v, want exactly one — the boundary control must clear the floor", got)
			}
		}
	}
}

// TestMultiLineResidualPlaceholderStillReported records what the filters do
// NOT catch, so the gap is visible instead of assumed away. A docker-compose
// secret whose value is a textbook placeholder ("changeme") still clears every
// filter: IsFalsePositiveSecret's kvPlaceholderRe is anchored ^...$ and its
// capture cannot cross the newline the docker_compose_secret pattern requires,
// so the key=value it looks for is never present in a multi-line span.
func TestMultiLineResidualPlaceholderStillReported(t *testing.T) {
	lines := []string{"env:", "  PASSWORD: \"changeme\""}
	got := NewMultiLineScanner(loadBuiltinRules(t), finding.SeverityLow).ScanMultiLine(lines, "fixture.txt", 1)
	t.Logf("placeholder value still reported: %v", multilineRuleNamesOf(got))
	if len(got) != 1 {
		t.Fatalf("findings = %v, want 1 — if this changes, re-check the claim above", multilineRuleNamesOf(got))
	}
}
