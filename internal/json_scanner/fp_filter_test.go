package json_scanner

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Batch 8 Task 1 — characterization of the four filters the RULESET branch of
// scanValue (scanner.go:90-124) was missing, and Task 2's gate on the fix. The
// plain-file path (internal/scanner/helpers.go:529-564) applies, in this order:
//
//	if rule.RequiresContext && !lineHasContextKeyword(line, rule.ContextKeywords) { continue }
//	... secret extraction, severity, entropy floor ...
//	if entropy.IsFalsePositiveSecret(secret) { continue }
//	if entropy.IsFalsePositiveToken(secret)  { continue }
//	if entropy.IsFalsePositiveEmail(secret)  { continue }
//
// That branch applied the entropy floor and none of those four filters, so every
// FP-shaped span below was reported here while the plain-file path dropped it.
// Task 2 closed the gap; the behavioral tests at the bottom pin the
// suppressed/survives split, and the premise table still shows exactly which
// filter removes which span.
//
// The KEY-NAME HEURISTIC at scanner.go:70-87 is deliberately NOT part of this
// batch (Batch 5 pinned it): it matches on a JSON key name, not on a rule, so
// it has no rule.ContextKeywords and no matched span to run the FP filters
// over. Every fixture below therefore uses a neutral key ("cfg", "contact")
// that secretKeyRE does not match, so the heuristic cannot contribute a finding
// and the ruleset branch is observed in isolation.
//
// WHAT `secret` IS. `rule.MatchAll` wraps regexp.FindAllStringIndex, so it
// returns only [start, end] of the whole match over the JSON VALUE — never a
// captured value. The spans asserted below are therefore whole matches, and
// every measurement was taken with entropy.Shannon over that same span.
//
// JSON-SPECIFIC SHAPE NOTES:
//   - reconFPPlaceholderValue-style fixtures need quotes inside a JSON string,
//     so they use single quotes: kvPlaceholderRe accepts ['"] for both the
//     opener and the closer, and generic_secret's pattern does too.
//   - The JSON key carries real source context that a plain file would get from
//     its line, so "contact" is used as a KEY for the email fixture; it is one
//     of email_address's context_keywords, which is what lets the RequiresContext
//     check pass there and leave IsFalsePositiveEmail as the only filter that
//     can reject the span.
const (
	jsonFPPlaceholderValue = "secret='user_name_d9f3a7c2b8e5d4'"
	jsonFPHyphenToken      = "hvs.a7f3-b9c2-d4e6-8f01"
	jsonFPImageEmail       = "opengraph-image@2x.jpeg"
	jsonNoContextAuth      = "Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	jsonCtxKeywordAuth     = "Authorization: Basic kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
	jsonSurvivorStripe     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	jsonEnvGenericCtx      = "MY_SECRET=kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
)

type jsonFPFixture struct {
	name          string
	key           string // JSON key; must not match secretKeyRE
	value         string // JSON string value
	rule          string // builtin rule that must match
	span          string // exact whole-match span
	minEnt        float64
	fpSecret      bool
	fpToken       bool
	fpEmail       bool
	wantNoContext bool
	kwInCtx       bool // a context keyword of the rule appears in key+value
	kwInSpan      bool
	kwInKey       bool
}

var jsonFPFixtures = []jsonFPFixture{
	{
		name: "placeholder_value", key: "cfg", value: jsonFPPlaceholderValue,
		rule: "generic_secret", span: jsonFPPlaceholderValue, minEnt: 2.0,
		fpSecret: true, wantNoContext: true,
	},
	{
		name: "hyphenated_token", key: "cfg", value: jsonFPHyphenToken,
		rule: "vault_token", span: jsonFPHyphenToken, minEnt: 2.0,
		fpToken: true, wantNoContext: true,
	},
	{
		// key "contact" satisfies email_address's context guard, isolating
		// IsFalsePositiveEmail. ".jpeg" (not ".png"/".js"/…) keeps
		// IsFalsePositiveToken's URL-path-segment branch from firing first.
		name: "image_filename_email", key: "contact", value: jsonFPImageEmail,
		rule: "email_address", span: jsonFPImageEmail, minEnt: 2.0,
		fpEmail: true, kwInCtx: true, kwInKey: true,
	},
	{
		name: "contextless_auth", key: "cfg", value: jsonNoContextAuth,
		rule: "basic_auth_header", span: jsonNoContextAuth, minEnt: 2.0,
	},
	{
		name: "context_keyword_auth", key: "authorization", value: jsonCtxKeywordAuth,
		rule: "basic_auth_header", span: jsonNoContextAuth, minEnt: 2.0,
		kwInCtx: true, kwInKey: true,
	},
	{
		name: "survivor_stripe", key: "cfg", value: jsonSurvivorStripe,
		rule: "stripe_secret_key", span: jsonSurvivorStripe, minEnt: 2.0,
		wantNoContext: true,
	},
	{
		name: "env_generic_secret", key: "cfg", value: jsonEnvGenericCtx,
		rule: "env_generic_secret", span: jsonEnvGenericCtx, minEnt: 3.0,
		kwInCtx: true, kwInSpan: true,
	},
}

func jsonDefaultRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	return rs
}

func jsonRule(t *testing.T, rs *rules.RuleSet, name string) *rules.Rule {
	t.Helper()
	for i := range rs.Rules {
		if rs.Rules[i].Name == name {
			return &rs.Rules[i]
		}
	}
	t.Fatalf("fixture rule %q is gone from the default ruleset", name)
	return nil
}

func jsonHasKeyword(text string, kws []string) bool {
	low := strings.ToLower(text)
	for _, kw := range kws {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func jsonMatchingSpan(r *rules.Rule, value string) string {
	for _, m := range r.MatchAll(value) {
		return value[m[0]:m[1]]
	}
	return ""
}

// TestJSONFPFixturePremises pins every premise the behavioral tests rest on, so
// a ruleset or heuristic change that invalidates a fixture fails here instead of
// silently turning the behavioral assertions into no-ops.
func TestJSONFPFixturePremises(t *testing.T) {
	rs := jsonDefaultRules(t)

	for _, fx := range jsonFPFixtures {
		t.Run(fx.name, func(t *testing.T) {
			if secretKeyRE.MatchString(fx.key) {
				t.Fatalf("fixture key %q matches secretKeyRE: the key-name heuristic at scanner.go:70 "+
					"would contribute findings of its own and the ruleset branch would not be isolated", fx.key)
			}
			r := jsonRule(t, rs, fx.rule)
			span := jsonMatchingSpan(r, fx.value)
			if span == "" {
				t.Fatalf("rule %q no longer matches JSON value %q", fx.rule, fx.value)
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
			// The context text this path can offer is the JSON key path plus the
			// value: the raw source line of {"key":"value"} contains both.
			if got := jsonHasKeyword(fx.key+" "+fx.value, r.ContextKeywords); got != fx.kwInCtx {
				t.Errorf("context keyword present in key+value: got %v, want %v", got, fx.kwInCtx)
			}
			if got := jsonHasKeyword(fx.key, r.ContextKeywords); got != fx.kwInKey {
				t.Errorf("context keyword present in the JSON key %q: got %v, want %v", fx.key, got, fx.kwInKey)
			}
			if got := jsonHasKeyword(span, r.ContextKeywords); got != fx.kwInSpan {
				t.Errorf("context keyword present in the match %q: got %v, want %v", span, got, fx.kwInSpan)
			}
		})
	}
}

// TestJSONEnvGenericSecretCanNeverBeContextless documents a premise the batch
// brief got wrong. env_generic_secret is named there as the context-less
// fixture, but its pattern
//
//	(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})
//
// forces a literal (_SECRET / _PASSWORD / _TOKEN / _API_KEY) that is itself one
// of its own context_keywords [secret token password key api auth access
// private]. Every possible match therefore carries a keyword inside the match,
// so a RequiresContext check whose text contains the match can never reject it —
// on this path or on the plain-file path, whose line also contains the match.
// jsonNoContextAuth (basic_auth_header) is used for the context fixture instead.
func TestJSONEnvGenericSecretCanNeverBeContextless(t *testing.T) {
	rs := jsonDefaultRules(t)
	r := jsonRule(t, rs, "env_generic_secret")
	if !r.RequiresContext {
		t.Fatal("env_generic_secret no longer sets requires_context: this test's premise changed")
	}
	for _, alt := range []string{"_SECRET=", "_PASSWORD=", "_TOKEN=", "_API_KEY="} {
		if !jsonHasKeyword(alt, r.ContextKeywords) {
			t.Errorf("pattern alternative %q carries none of the rule's context keywords %v; "+
				"a context-less env_generic_secret match may now be constructible and this "+
				"test's conclusion needs re-checking", alt, r.ContextKeywords)
		}
	}
}

func jsonFixtureByName(t *testing.T, name string) jsonFPFixture {
	t.Helper()
	for _, fx := range jsonFPFixtures {
		if fx.name == name {
			return fx
		}
	}
	t.Fatalf("no fixture named %q", name)
	return jsonFPFixture{}
}

// jsonFixtureRuleName is the rule name scanValue emits: "json_" + rule.Name.
func jsonFixtureRuleName(fx jsonFPFixture) string { return "json_" + fx.rule }

// jsonReports drives the fixture through ScanJSONFile with its neutral key.
func jsonReports(t *testing.T, fx jsonFPFixture) bool {
	t.Helper()
	rs := jsonDefaultRules(t)
	content := `{"` + fx.key + `":"` + fx.value + `"}`
	return countRule(ScanJSONFile("app.json", content, rs, finding.SeverityLow), jsonFixtureRuleName(fx)) > 0
}

// TestJSONFPShapedMatchesAreSuppressed guards the three false-positive filters
// added to the ruleset branch of scanValue (mirroring helpers.go:555-563). Each
// of these spans was REPORTED before the filters landed — that was the
// characterization recorded in the previous commit, and the fixture premises
// above still assert exactly which filter rejects each one and why.
func TestJSONFPShapedMatchesAreSuppressed(t *testing.T) {
	for _, name := range []string{"placeholder_value", "hyphenated_token", "image_filename_email"} {
		fx := jsonFixtureByName(t, name)
		if jsonReports(t, fx) {
			t.Fatalf("%s: %s still reported value %q (entropy %.4f clears the floor). The FP filter "+
				"this fixture isolates is no longer applied on this path, or it changed shape.",
				fx.name, jsonFixtureRuleName(fx), fx.value, entropy.Shannon(fx.span))
		}
	}
}

// TestJSONContextlessMatchIsSuppressed guards the RequiresContext guard added
// to this path, checked against the JSON key path plus the value (see the
// context-text decision recorded at the call site).
func TestJSONContextlessMatchIsSuppressed(t *testing.T) {
	fx := jsonFixtureByName(t, "contextless_auth")
	if jsonReports(t, fx) {
		t.Fatalf("context-less %s match on value %q still reported: neither the key %q nor the value "+
			"carries any of the rule's context keywords %v, so RequiresContext should have dropped it",
			jsonFixtureRuleName(fx), fx.value, fx.key, jsonKeywordList(t, fx))
	}
}

// TestJSONControlsReported pins the controls that must keep producing a finding
// now that the filters are live. context_keyword_auth is the negative control
// for the context guard: the JSON key "authorization" satisfies it even though
// the value alone does not, which is what makes the key-path-plus-value choice
// observable rather than accidental.
func TestJSONControlsReported(t *testing.T) {
	for _, name := range []string{"context_keyword_auth", "survivor_stripe", "env_generic_secret"} {
		fx := jsonFixtureByName(t, name)
		if !jsonReports(t, fx) {
			t.Fatalf("%s: control %s match on value %q stopped being reported: the filters suppressed "+
				"a match that clears the floor and trips none of them",
				fx.name, jsonFixtureRuleName(fx), fx.value)
		}
	}
}

func jsonKeywordList(t *testing.T, fx jsonFPFixture) []string {
	t.Helper()
	rs := jsonDefaultRules(t)
	return jsonRule(t, rs, fx.rule).ContextKeywords
}
