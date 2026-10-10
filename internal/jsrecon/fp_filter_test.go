package jsrecon

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Batch 8 Task 1 — characterization of the four filters scanReconstructed is
// MISSING. The plain-file path (internal/scanner/helpers.go:529-564) applies,
// in this order:
//
//	if rule.RequiresContext && !lineHasContextKeyword(line, rule.ContextKeywords) { continue }
//	... secret extraction, severity, entropy floor ...
//	if entropy.IsFalsePositiveSecret(secret) { continue }
//	if entropy.IsFalsePositiveToken(secret)  { continue }
//	if entropy.IsFalsePositiveEmail(secret)  { continue }
//
// scanReconstructed applied the entropy floor (decoder.RuleEntropyFloor, since
// Batch 5) and nothing else: every span below was reported here while the
// plain-file path dropped it. Batch 8 closed that gap, and the behavioral
// tests at the bottom now pin the suppressed/supplied split. The premise table
// is unchanged, so it still shows exactly which filter removes which span.
//
// WHAT `secret` IS. `rule.MatchAll` wraps regexp.FindAllStringIndex, so it
// returns only [start, end] of the whole match — never a captured value. The
// spans asserted below are therefore whole matches; every measurement was
// taken with entropy.Shannon over the same span the production code slices.
//
// FIXTURES. Each one was chosen by reading entropy.go and then MEASURED (see
// TestReconFPFixturePremises, which fails if any of these drift):
//
//   - reconFPPlaceholderValue: `generic_secret` / `dotenv_secret` match
//     secret='user_name_d9f3a7c2b8e5d4'. entropy.IsFalsePositiveSecret pulls
//     the quoted value out via kvPlaceholderRe
//     (^(?:[a-z][a-z0-9]*[-_]?){1,4}\s*[:=]\s*['"](.+?)['"]$) and hands it to
//     IsFalsePositiveToken, whose snake_case branch fires: the value is
//     lower-case+digits+underscores only, carries no "+/=-", and its
//     letter/digit class changes more than 5 times (u|s|e|r|_|n|a|m|e|_|d|9|f|3|a|7|…).
//     It is a config key name sitting in a secret-shaped slot, not a secret.
//     Neither rule sets requires_context, so only IsFalsePositiveSecret can
//     remove this finding — the fixture isolates that one filter.
//
//   - reconFPHyphenToken: `vault_token` matches hvs.a7f3-b9c2-d4e6-8f01.
//     This fixture was written to isolate IsFalsePositiveToken's hyphenated
//     flag-name branch (strings.Count >= 3 && len > 20). That was wrong: a
//     HashiCorp Vault token is a CRITICAL credential, not a flag name, and no
//     rule in builtin.yaml matches a flag-name-shaped string — so the only
//     hyphenated match the ruleset can produce is a credential. The
//     hyphen-branch fix narrowed the test to require short lowercase segments,
//     and this fixture now asserts the token SURVIVES. Same isolation argument:
//     vault_token has no requires_context and the span trips neither
//     IsFalsePositiveSecret (no "[:=]" for kvPlaceholderRe to anchor on) nor
//     IsFalsePositiveEmail (no image extension).
//
//   - reconFPImageEmail: `email_address` matches opengraph-image@2x.jpeg.
//     IsFalsePositiveEmail rejects any span ending in an image/font extension.
//     The extension is .jpeg on purpose: IsFalsePositiveToken's URL-path-segment
//     branch lists only .png/.jpg/.svg/.js/.css/.woff, so with .jpeg only the
//     Email filter can reject this span — otherwise the earlier Token filter
//     would mask it and the Email call could never be observed firing. The
//     leading "contact " is one of email_address's context_keywords, so this
//     fixture also proves RequiresContext PASSES here (see the context-text
//     decision recorded at the call site).
//
//   - reconNoContextAuth: `basic_auth_header` matches
//     Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO. Its only context keyword is
//     "authorization", which appears neither in the span nor anywhere in the
//     reconstructed text, and none of the three FP filters fire on the span, so
//     only RequiresContext can reject it.
//
// CONTROLS (reported before AND after the change): reconCtxKeywordAuth is the
// same match with "Authorization: " in front of it, reconSurvivorStripe is a
// high-entropy threshold-less key that trips no FP filter, and
// reconEnvGenericCtx is the brief's named rule — see the note on it below.
const (
	reconFPPlaceholderValue = "secret='user_name_d9f3a7c2b8e5d4'"
	reconFPHyphenToken      = "hvs.a7f3-b9c2-d4e6-8f01"
	reconFPImageEmail       = "contact opengraph-image@2x.jpeg"
	reconNoContextAuth      = "Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	reconCtxKeywordAuth     = "Authorization: Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	reconSurvivorStripe     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	reconEnvGenericCtx      = "MY_SECRET=kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
)

// reconFixture is one row of the premise table below.
type reconFixture struct {
	name     string
	text     string // reconstructed text the fixture drives
	rule     string // builtin rule that must match it
	span     string // exact whole-match span that must be sliced
	minEnt   float64
	fpSecret bool
	fpToken  bool
	fpEmail  bool
	// wantNoContext means the matching rule must NOT set requires_context, i.e.
	// the FP filters cannot be masked by the context guard on this path.
	wantNoContext bool
	// kwInText / kwInSpan record where the rule's context keywords appear, and
	// are what the RequiresContext assertion is derived from.
	kwInText bool
	kwInSpan bool
}

var reconFPFixtures = []reconFixture{
	{
		name: "placeholder_value", text: reconFPPlaceholderValue,
		rule: "generic_secret", span: reconFPPlaceholderValue, minEnt: 2.0,
		fpSecret: true, wantNoContext: true,
	},
	{
		name: "vault_token_survives", text: reconFPHyphenToken,
		rule: "vault_token", span: reconFPHyphenToken, minEnt: 2.0,
		fpToken: false, wantNoContext: true,
	},
	{
		name: "image_filename_email", text: reconFPImageEmail,
		rule: "email_address", span: "opengraph-image@2x.jpeg", minEnt: 2.0,
		fpEmail: true, kwInText: true,
	},
	{
		name: "contextless_auth", text: reconNoContextAuth,
		rule: "basic_auth_header", span: reconNoContextAuth, minEnt: 2.0,
	},
	{
		name: "context_keyword_auth", text: reconCtxKeywordAuth,
		rule: "basic_auth_header", span: reconNoContextAuth, minEnt: 2.0,
		kwInText: true,
	},
	{
		name: "survivor_stripe", text: reconSurvivorStripe,
		rule: "stripe_secret_key", span: reconSurvivorStripe, minEnt: 2.0,
		wantNoContext: true,
	},
	{
		name: "env_generic_secret", text: reconEnvGenericCtx,
		rule: "env_generic_secret", span: reconEnvGenericCtx, minEnt: 3.0,
		kwInText: true, kwInSpan: true,
	},
}

// reconDefaultRules loads the shipped ruleset once per test.
func reconDefaultRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return rs
}

func reconRule(t *testing.T, rs *rules.RuleSet, name string) *rules.Rule {
	t.Helper()
	for i := range rs.Rules {
		if rs.Rules[i].Name == name {
			return &rs.Rules[i]
		}
	}
	t.Fatalf("fixture rule %q is gone from the default ruleset", name)
	return nil
}

// reconSpanHasKeyword reports whether the match itself carries one of the
// rule's context keywords.
func reconSpanHasKeyword(span string, kws []string) bool {
	low := strings.ToLower(span)
	for _, kw := range kws {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// reconMatchingSpan returns the span the named rule produces over text, or "".
func reconMatchingSpan(r *rules.Rule, text string) string {
	for _, m := range r.MatchAll(text) {
		return text[m[0]:m[1]]
	}
	return ""
}

// TestReconFPFixturePremises pins every premise the behavioral tests below are
// built on. It asserts against the shipped ruleset and the shipped filters
// directly, so a ruleset or heuristic change that quietly invalidates a fixture
// fails here instead of turning the behavioral assertions into no-ops.
func TestReconFPFixturePremises(t *testing.T) {
	rs := reconDefaultRules(t)

	for _, fx := range reconFPFixtures {
		t.Run(fx.name, func(t *testing.T) {
			r := reconRule(t, rs, fx.rule)
			span := reconMatchingSpan(r, fx.text)
			if span == "" {
				t.Fatalf("rule %q no longer matches fixture %q", fx.rule, fx.text)
			}
			if span != fx.span {
				t.Fatalf("rule %q matched %q, fixture asserts %q", fx.rule, span, fx.span)
			}
			e := entropy.Shannon(span)
			if e < fx.minEnt {
				t.Fatalf("span %q entropy %.4f, want >= %.1f: the fixture no longer clears the floor it "+
					"is meant to test, so the filter under test would be masked by the floor",
					span, e, fx.minEnt)
			}
			if got := entropy.IsFalsePositiveSecret(span); got != fx.fpSecret {
				t.Errorf("IsFalsePositiveSecret(%q) = %v, want %v", span, got, fx.fpSecret)
			}
			if got := entropy.IsFalsePositiveToken(span); got != fx.fpToken {
				t.Errorf("IsFalsePositiveToken(%q) = %v, want %v", span, got, fx.fpToken)
			}
			if got := entropy.IsFalsePositiveEmail(span); got != fx.fpEmail {
				t.Errorf("IsFalsePositiveEmail(%q) = %v, want %v", span, got, fx.fpEmail)
			}
			if fx.wantNoContext && r.RequiresContext {
				t.Errorf("rule %q sets requires_context; this fixture is meant to isolate an FP filter, "+
					"but RequiresContext runs first and would mask it", fx.rule)
			}
			if !fx.wantNoContext && !r.RequiresContext {
				t.Errorf("rule %q does not set requires_context, so this fixture cannot test the "+
					"context guard", fx.rule)
			}
			if got := reconSpanHasKeyword(fx.text, r.ContextKeywords); got != fx.kwInText {
				t.Errorf("context keyword present in the reconstructed text %q: got %v, want %v",
					fx.text, got, fx.kwInText)
			}
			if got := reconSpanHasKeyword(span, r.ContextKeywords); got != fx.kwInSpan {
				t.Errorf("context keyword present in the match %q: got %v, want %v", span, got, fx.kwInSpan)
			}
		})
	}
}

// TestReconEnvGenericSecretCanNeverBeContextless documents a premise the batch
// brief got wrong. env_generic_secret is named there as the fixture for a
// context-less match, but its pattern is
//
//	(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})
//
// and its context_keywords are [secret token password key api auth access
// private]. Every one of those four alternatives contains a literal that IS one
// of its own context keywords (_SECRET / _PASSWORD / _TOKEN / _API_KEY), so
// every possible match of this rule carries a keyword inside the match itself.
// Any RequiresContext check whose text contains the match therefore passes for
// this rule — including the plain-file path's line-based check, since the line
// contains the match. env_generic_secret cannot be the context-less fixture;
// reconNoContextAuth (basic_auth_header) is used for that instead.
//
// What DOES change for env_generic_secret on these paths is the FP filters; the
// fixture above shows it is FP-clean, so it is expected to survive — and it does
// (TestReconstructControlsReported).
func TestReconEnvGenericSecretCanNeverBeContextless(t *testing.T) {
	rs := reconDefaultRules(t)
	r := reconRule(t, rs, "env_generic_secret")
	if !r.RequiresContext {
		t.Fatal("env_generic_secret no longer sets requires_context: this test's premise changed")
	}
	for _, alt := range []string{"_SECRET=", "_PASSWORD=", "_TOKEN=", "_API_KEY="} {
		if !reconSpanHasKeyword(alt, r.ContextKeywords) {
			t.Errorf("pattern alternative %q carries none of the rule's context keywords %v; "+
				"a context-less env_generic_secret match may now be constructible and this "+
				"test's conclusion needs re-checking", alt, r.ContextKeywords)
		}
	}
}

// reconFindingsFor returns the findings attributed to ruleSuffix.
func reconFindingsFor(findings []finding.Finding, ruleSuffix string) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if strings.HasSuffix(f.RuleName, ruleSuffix) {
			out = append(out, f)
		}
	}
	return out
}

// reconSuppressed drives scanReconstructed through ReconstructAndScan and
// reports whether the fixture's rule produced a finding.
func reconSuppressed(t *testing.T, fx reconFixture) bool {
	t.Helper()
	rs := reconDefaultRules(t)
	got := ReconstructAndScan(jsReconstructedTo(fx.text), "app.js", rs, finding.SeverityLow)
	return len(reconFindingsFor(got, fx.rule)) > 0
}

// TestReconstructFPShapedMatchesAreSuppressed guards the three false-positive
// filters added to scanReconstructed (mirroring helpers.go:555-563). Each of
// these spans was REPORTED before the filters landed — that was the
// characterization recorded in the previous commit, and the fixture premises
// above still assert exactly which filter rejects each one and why.
func TestReconstructFPShapedMatchesAreSuppressed(t *testing.T) {
	for _, name := range []string{"placeholder_value", "image_filename_email"} {
		fx := reconFixtureByName(t, name)
		if reconSuppressed(t, fx) {
			t.Fatalf("%s: %s still reported %q (entropy %.4f clears the floor). The FP filter this "+
				"fixture isolates is no longer applied on this path, or it changed shape.",
				fx.name, fx.rule, fx.text, entropy.Shannon(fx.span))
		}
	}
}

// TestReconstructContextlessMatchIsSuppressed guards the RequiresContext guard
// added to scanReconstructed, checked against the reconstructed text (see the
// context-text decision recorded at the call site).
func TestReconstructContextlessMatchIsSuppressed(t *testing.T) {
	fx := reconFixtureByName(t, "contextless_auth")
	if reconSuppressed(t, fx) {
		t.Fatalf("context-less %s match on %q still reported: the reconstructed text carries none of "+
			"the rule's context keywords %v, so RequiresContext should have dropped it",
			fx.rule, fx.text, reconKeywordList(t, fx))
	}
}

// TestReconstructControlsReported pins the three controls that must keep
// producing a finding now that the filters are live. context_keyword_auth is
// the negative control for the context guard (same match, keyword present in
// the reconstructed text — proving the guard is not simply "drop every
// requires_context rule"), survivor_stripe is FP-clean, and env_generic_secret
// carries its keyword inside the match.
func TestReconstructControlsReported(t *testing.T) {
	for _, name := range []string{"context_keyword_auth", "survivor_stripe", "env_generic_secret"} {
		fx := reconFixtureByName(t, name)
		if !reconSuppressed(t, fx) {
			t.Fatalf("%s: control %s match on %q stopped being reported: the filters suppressed a "+
				"match that clears the floor and trips none of them", fx.name, fx.rule, fx.text)
		}
	}
}

func reconKeywordList(t *testing.T, fx reconFixture) []string {
	t.Helper()
	rs := reconDefaultRules(t)
	return reconRule(t, rs, fx.rule).ContextKeywords
}

func reconFixtureByName(t *testing.T, name string) reconFixture {
	t.Helper()
	for _, fx := range reconFPFixtures {
		if fx.name == name {
			return fx
		}
	}
	t.Fatalf("no fixture named %q", name)
	return reconFixture{}
}
