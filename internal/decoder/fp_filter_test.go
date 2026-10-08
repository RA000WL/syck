package decoder

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Batch 8 Task 1 — characterization of the two filters scanDecodedChunk was
// MISSING, and Task 2's gate on the fix. The plain-file path
// (internal/scanner/helpers.go:529-564) applies, in this order:
//
//	if rule.RequiresContext && !lineHasContextKeyword(line, rule.ContextKeywords) { continue }
//	... secret extraction, severity, entropy floor ...
//	if entropy.IsFalsePositiveSecret(secret) { continue }
//	if entropy.IsFalsePositiveToken(secret)  { continue }
//	if entropy.IsFalsePositiveEmail(secret)  { continue }
//
// scanDecodedChunk (pipeline.go:167-176) applied the floor, then Token at 171
// and Email at 174. It was MISSING only IsFalsePositiveSecret and
// RequiresContext, so this file characterizes those two and pins the two that
// already existed as "suppressed before AND after" — that is the guard against
// double-applying them. Task 2 closed the gap; the behavioral tests at the
// bottom pin the suppressed/survives split, and the premise table still shows
// exactly which filter removes which span.
//
// WHAT `secret` IS. `rule.MatchAll` wraps regexp.FindAllStringIndex, so it
// returns only [start, end] of the whole match over the DECODED CHUNK — never a
// captured value. Measurements below were taken with entropy.Shannon over that
// same span.
//
// FIXTURES (same shapes as the jsrecon and json_scanner files, driven through
// base64 so they arrive via scanDecodedChunk):
//
//   - decodedFPPlaceholderValue: generic_secret / dotenv_secret match
//     secret='user_name_d9f3a7c2b8e5d4'. IsFalsePositiveSecret extracts the
//     quoted value (kvPlaceholderRe) and IsFalsePositiveToken's snake_case
//     branch rejects it — a config key name in a secret-shaped slot. Those rules
//     set no requires_context, so this isolates IsFalsePositiveSecret.
//     terraform_sensitive_var matches the same span and requires_context, so it
//     is masked by the context guard rather than the FP filter; either way the
//     span stops being reported, which is what the behavioral assertions below
//     check. See decodedReportsSpan for why they are span-based here.
//   - decodedNoContextAuth: basic_auth_header matches
//     Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO; its only context keyword
//     ("authorization") is nowhere in the decoded chunk, and no FP filter fires
//     on the span, so only RequiresContext can reject it.
//   - decodedFPHyphenToken / decodedFPImageEmail: already suppressed by the
//     Token (171) and Email (174) calls that exist today. They must stay
//     suppressed after this batch and must not be reported twice-suppressed.
const (
	decodedFPPlaceholderValue = "secret='user_name_d9f3a7c2b8e5d4'"
	decodedFPHyphenToken      = "hvs.a7f3-b9c2-d4e6-8f01"
	decodedFPImageEmail       = "contact opengraph-image@2x.jpeg"
	decodedNoContextAuth      = "Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	decodedCtxKeywordAuth     = "Authorization: Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	decodedSurvivorStripe     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	decodedEnvGenericCtx      = "MY_SECRET=kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
)

type decodedFPFixture struct {
	name          string
	text          string // decoded chunk the fixture drives
	rule          string // builtin rule that must match
	span          string // exact whole-match span
	minEnt        float64
	fpSecret      bool
	fpToken       bool
	fpEmail       bool
	wantNoContext bool
	kwInText      bool
	kwInSpan      bool
}

var decodedFPFixtures = []decodedFPFixture{
	{
		name: "placeholder_value", text: decodedFPPlaceholderValue,
		rule: "generic_secret", span: decodedFPPlaceholderValue, minEnt: 2.0,
		fpSecret: true, wantNoContext: true,
	},
	{
		name: "hyphenated_token", text: decodedFPHyphenToken,
		rule: "vault_token", span: decodedFPHyphenToken, minEnt: 2.0,
		fpToken: true, wantNoContext: true,
	},
	{
		name: "image_filename_email", text: decodedFPImageEmail,
		rule: "email_address", span: "opengraph-image@2x.jpeg", minEnt: 2.0,
		fpEmail: true, kwInText: true,
	},
	{
		name: "contextless_auth", text: decodedNoContextAuth,
		rule: "basic_auth_header", span: decodedNoContextAuth, minEnt: 2.0,
	},
	{
		name: "context_keyword_auth", text: decodedCtxKeywordAuth,
		rule: "basic_auth_header", span: decodedNoContextAuth, minEnt: 2.0,
		kwInText: true,
	},
	{
		name: "survivor_stripe", text: decodedSurvivorStripe,
		rule: "stripe_secret_key", span: decodedSurvivorStripe, minEnt: 2.0,
		wantNoContext: true,
	},
	{
		name: "env_generic_secret", text: decodedEnvGenericCtx,
		rule: "env_generic_secret", span: decodedEnvGenericCtx, minEnt: 3.0,
		kwInText: true, kwInSpan: true,
	},
}

func decodedDefaultRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return rs
}

func decodedRule(t *testing.T, rs *rules.RuleSet, name string) *rules.Rule {
	t.Helper()
	for i := range rs.Rules {
		if rs.Rules[i].Name == name {
			return &rs.Rules[i]
		}
	}
	t.Fatalf("fixture rule %q is gone from the default ruleset", name)
	return nil
}

func decodedHasKeyword(text string, kws []string) bool {
	low := strings.ToLower(text)
	for _, kw := range kws {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func decodedMatchingSpan(r *rules.Rule, text string) string {
	for _, m := range r.MatchAll(text) {
		return text[m[0]:m[1]]
	}
	return ""
}

// decodedBase64Line wraps text so DecodeAndRescan's base64 decoder recovers it
// verbatim as the scanned chunk.
func decodedBase64Line(text string) string {
	return `const blob = "` + base64.StdEncoding.EncodeToString([]byte(text)) + `"`
}

// TestDecodedFPFixturePremises pins every premise the behavioral tests rest on.
func TestDecodedFPFixturePremises(t *testing.T) {
	rs := decodedDefaultRules(t)

	for _, fx := range decodedFPFixtures {
		t.Run(fx.name, func(t *testing.T) {
			r := decodedRule(t, rs, fx.rule)
			span := decodedMatchingSpan(r, fx.text)
			if span == "" {
				t.Fatalf("rule %q no longer matches decoded chunk %q", fx.rule, fx.text)
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
			if got := decodedHasKeyword(fx.text, r.ContextKeywords); got != fx.kwInText {
				t.Errorf("context keyword present in the decoded chunk %q: got %v, want %v", fx.text, got, fx.kwInText)
			}
			if got := decodedHasKeyword(span, r.ContextKeywords); got != fx.kwInSpan {
				t.Errorf("context keyword present in the match %q: got %v, want %v", span, got, fx.kwInSpan)
			}
		})
	}
}

// TestDecodedEnvGenericSecretCanNeverBeContextless documents a premise the batch
// brief got wrong. env_generic_secret is named there as the context-less
// fixture, but its pattern
//
//	(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})
//
// forces a literal (_SECRET / _PASSWORD / _TOKEN / _API_KEY) that is itself one
// of its own context_keywords [secret token password key api auth access
// private]. Every possible match therefore carries a keyword inside the match,
// so no RequiresContext check whose text contains the match can reject it.
// decodedNoContextAuth (basic_auth_header) is used for the context fixture instead.
func TestDecodedEnvGenericSecretCanNeverBeContextless(t *testing.T) {
	rs := decodedDefaultRules(t)
	r := decodedRule(t, rs, "env_generic_secret")
	if !r.RequiresContext {
		t.Fatal("env_generic_secret no longer sets requires_context: this test's premise changed")
	}
	for _, alt := range []string{"_SECRET=", "_PASSWORD=", "_TOKEN=", "_API_KEY="} {
		if !decodedHasKeyword(alt, r.ContextKeywords) {
			t.Errorf("pattern alternative %q carries none of the rule's context keywords %v; "+
				"a context-less env_generic_secret match may now be constructible and this "+
				"test's conclusion needs re-checking", alt, r.ContextKeywords)
		}
	}
}

func decodedFixtureByName(t *testing.T, name string) decodedFPFixture {
	t.Helper()
	for _, fx := range decodedFPFixtures {
		if fx.name == name {
			return fx
		}
	}
	t.Fatalf("no fixture named %q", name)
	return decodedFPFixture{}
}

// decodedReportsSpan drives the fixture's text through DecodeAndRescan as a
// base64 blob and reports whether ANY finding carries the fixture's span.
//
// Assertions here are span-based rather than rule-name-based, unlike the
// jsrecon and json_scanner files. scanDecodedChunk dedupes by secret value
// (pipeline.go:178-187: a match whose secret equals an already-emitted finding
// is dropped), so when several rules match the same span only the first one in
// ruleset order survives. For the placeholder fixture that survivor is
// terraform_sensitive_var, not generic_secret — and after this batch both are
// removed anyway (one by RequiresContext, one by IsFalsePositiveSecret), so
// "is this span reported at all" is the stable question. It is also the one
// users see.
func decodedReportsSpan(t *testing.T, fx decodedFPFixture) bool {
	t.Helper()
	rs := decodedDefaultRules(t)
	got := DecodeAndRescan(decodedBase64Line(fx.text), "app.js", 1, rs, finding.SeverityLow, Flags{Base64: true})
	for _, f := range got {
		if f.Secret == fx.span {
			return true
		}
	}
	return false
}

// TestDecodedPlaceholderValueMatchIsSuppressed guards IsFalsePositiveSecret,
// which this path was missing. The decoded chunk's
// secret='user_name_d9f3a7c2b8e5d4' span was REPORTED before the filter landed
// — that was the characterization recorded in the previous commit. Three rules
// match that span (terraform_sensitive_var, generic_secret, dotenv_secret);
// after the fix two are dropped by RequiresContext and generic_secret by the FP
// filter, and the dedup means whichever fired first used to be the only one a
// user saw.
func TestDecodedPlaceholderValueMatchIsSuppressed(t *testing.T) {
	fx := decodedFixtureByName(t, "placeholder_value")
	if decodedReportsSpan(t, fx) {
		t.Fatalf("span %q (decoded chunk %q) still reported: IsFalsePositiveSecret must drop a quoted "+
			"snake_case key name sitting in a secret-shaped slot", fx.span, fx.text)
	}
}

// TestDecodedContextlessMatchIsSuppressed guards the RequiresContext guard,
// checked against the decoded chunk (see the context-text decision recorded at
// the call site).
func TestDecodedContextlessMatchIsSuppressed(t *testing.T) {
	fx := decodedFixtureByName(t, "contextless_auth")
	if decodedReportsSpan(t, fx) {
		t.Fatalf("context-less span %q (decoded chunk %q) still reported: the decoded text carries "+
			"none of the rule's context keywords %v, so RequiresContext should have dropped it",
			fx.span, fx.text, decodedKeywordList(t, fx))
	}
}

// TestDecodedTokenAndEmailAlreadyApplied pins the two filters this path already
// had (pipeline.go:171 and :174). They suppressed these spans before this batch
// and must keep suppressing them after — this is the regression guard against
// double-applying them when completing the filter list, and against a future
// edit that deletes the existing calls believing the batch owns them.
func TestDecodedTokenAndEmailAlreadyApplied(t *testing.T) {
	for _, name := range []string{"hyphenated_token", "image_filename_email"} {
		fx := decodedFixtureByName(t, name)
		if decodedReportsSpan(t, fx) {
			t.Fatalf("%s: %s already filters this span (Token at pipeline.go:171 / Email at :174); "+
				"expected suppression before AND after this batch", fx.name, fx.rule)
		}
	}
}

// TestDecodedControlsReported pins the controls that must keep producing a
// finding now that the filters are live. context_keyword_auth is the negative
// control for the context guard: the decoded chunk carries "Authorization", so
// the same match that is dropped without it is kept with it.
func TestDecodedControlsReported(t *testing.T) {
	for _, name := range []string{"context_keyword_auth", "survivor_stripe", "env_generic_secret"} {
		fx := decodedFixtureByName(t, name)
		if !decodedReportsSpan(t, fx) {
			t.Fatalf("%s: control span %q (decoded chunk %q) stopped being reported: the filters "+
				"suppressed a match that clears the floor and trips none of them",
				fx.name, fx.span, fx.text)
		}
	}
}

func decodedKeywordList(t *testing.T, fx decodedFPFixture) []string {
	t.Helper()
	rs := decodedDefaultRules(t)
	return decodedRule(t, rs, fx.rule).ContextKeywords
}
