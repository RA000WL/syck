package json_scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Characterization of the two entropy gates in this file, which are NOT the
// same thing and must not be unified:
//
//   - scanner.go:111 `if e < decoder.RuleEntropyFloor(...)` — the RULE-MATCH gate over each
//     `rs.Rules` entry. This is the one this batch changes to honor the rule's
//     own entropy_threshold.
//   - scanner.go:71 `e >= 3.0` — the KEY-NAME HEURISTIC gate, guarded by
//     `secretKeyRE.MatchString(keyName)`. Not a rule match; there is no `rule`
//     in scope to read a threshold from. It legitimately keeps its own 3.0.
//
// WHAT `e` IS COMPUTED OVER at line 111. `rule.MatchAll` wraps
// `regexp.FindAllStringIndex` and returns only [start, end] of the whole match —
// no submatch indices. env_generic_secret's pattern
//
//	(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})
//
// has no capturing group (verified: FindAllStringSubmatch returns exactly 1
// element). So `secret = v[m[0]:m[1]]` is the whole `KEY=value` string, NOT
// just the value. Measured with entropy.Shannon:
//
//	"MY_SECRET=aaaaaaaa"             Shannon = 2.7250  → in [2.0, 3.0)
//	"MY_SECRET=aaaaaaaaaaaaaaaa"     Shannon = 2.1620  → in [2.0, 3.0)
//	"MY_SECRET=abcdabcdabcdabcd"     Shannon = 3.3930  → above 3.0
//	"MY_SECRET=kR7mZp2WqL9xVb3HjT"   Shannon = 4.5930  → above 3.0
//
// Contrast: the value sub-span alone scores 0.0000 / 0.0000 / 2.0000 / 4.1700,
// so the 3.0 floor is largely satisfied by the key name, not the secret.
const (
	jsonLowSecretA  = "MY_SECRET=aaaaaaaa"
	jsonLowSecretB  = "MY_SECRET=aaaaaaaaaaaaaaaa"
	jsonHighSecretA = "MY_SECRET=abcdabcdabcdabcd"
	jsonHighSecretB = "MY_SECRET=kR7mZp2WqL9xVb3HjT"
)

func requireJSONEntropyBands(t *testing.T) {
	t.Helper()
	for _, s := range []string{jsonLowSecretA, jsonLowSecretB} {
		if e := entropy.Shannon(s); e < 2.0 || e >= 3.0 {
			t.Fatalf("%q entropy = %v, want [2.0, 3.0)", s, e)
		}
	}
	for _, s := range []string{jsonHighSecretA, jsonHighSecretB} {
		if e := entropy.Shannon(s); e <= 3.0 {
			t.Fatalf("%q entropy = %v, want > 3.0", s, e)
		}
	}
}

func countRule(findings []finding.Finding, ruleName string) int {
	n := 0
	for _, f := range findings {
		if f.RuleName == ruleName {
			n++
		}
	}
	return n
}

// TestJSONRuleMatchEntropyFloorHonorsRuleThreshold guards the rule-match gate at
// scanner.go:111. Before it consulted decoder.RuleEntropyFloor(rule.EntropyThreshold),
// every rule got the hardcoded global 2.0 floor, so a match in [2.0, 3.0) was
// reported from a JSON value even though env_generic_secret's own 3.0 threshold
// suppresses it on the plain-file path. The subtests below pin the fixed
// behavior in both directions.
//
// The JSON key is a neutral name ("cfg") that secretKeyRE does not match, so
// the key-name heuristic at scanner.go:75 cannot contribute findings and the
// ruleset branch is observed in isolation.
func TestJSONRuleMatchEntropyFloorHonorsRuleThreshold(t *testing.T) {
	requireJSONEntropyBands(t)
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	const ruleName = "json_env_generic_secret"

	t.Run("low_entropy_a_suppressed", func(t *testing.T) {
		content := `{"cfg":"` + jsonLowSecretA + `"}`
		got := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
		if n := countRule(got, ruleName); n != 0 {
			t.Fatalf("entropy %.4f under env_generic_secret's 3.0 threshold: expected suppression, got %d %s findings: %+v",
				entropy.Shannon(jsonLowSecretA), n, ruleName, got)
		}
	})

	t.Run("low_entropy_b_suppressed", func(t *testing.T) {
		content := `{"cfg":"` + jsonLowSecretB + `"}`
		got := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
		if n := countRule(got, ruleName); n != 0 {
			t.Fatalf("entropy %.4f under env_generic_secret's 3.0 threshold: expected suppression, got %d %s findings: %+v",
				entropy.Shannon(jsonLowSecretB), n, ruleName, got)
		}
	})

	t.Run("high_entropy_a_reported", func(t *testing.T) {
		content := `{"cfg":"` + jsonHighSecretA + `"}`
		got := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
		if n := countRule(got, ruleName); n != 1 {
			t.Fatalf("entropy %.4f above 3.0: expected 1 finding; got %d %s findings: %+v",
				entropy.Shannon(jsonHighSecretA), n, ruleName, got)
		}
	})

	t.Run("high_entropy_b_reported", func(t *testing.T) {
		content := `{"cfg":"` + jsonHighSecretB + `"}`
		got := ScanJSONFile("app.json", content, rs, finding.SeverityLow)
		if n := countRule(got, ruleName); n != 1 {
			t.Fatalf("entropy %.4f above 3.0: expected 1 finding; got %d %s findings: %+v",
				entropy.Shannon(jsonHighSecretB), n, ruleName, got)
		}
	})
}

// TestJSONKeyNameHeuristicFloorUnaffected guards scanner.go:75. That `e >= 3.0`
// belongs to the secret-key-NAME heuristic, not to a rule, so it must keep its
// own 3.0 floor and must NOT be rewritten to read a rule threshold. The rule
// name it emits is "json_" + keyName, i.e. `json_password`.
//
// Measured: "ZqZqWwWwWwWwXxXx" = 2.5000 (suppressed), "kR7mZp2WqL9xVb3HjT" =
// 4.1700 (reported).
func TestJSONKeyNameHeuristicFloorUnaffected(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	const heuristicRule = "json_password"

	below := "ZqZqWwWwWwWwXxXx"
	if e := entropy.Shannon(below); e < 2.0 || e >= 3.0 {
		t.Fatalf("below-floor fixture entropy = %v, want [2.0, 3.0)", e)
	}
	t.Run("below_three_suppressed", func(t *testing.T) {
		content := `{"password":"` + below + `"}`
		if n := countRule(ScanJSONFile("app.json", content, rs, finding.SeverityLow), heuristicRule); n != 0 {
			t.Fatalf("entropy %.4f under the heuristic's own 3.0 floor: expected 0 findings, got %d",
				entropy.Shannon(below), n)
		}
	})

	above := "kR7mZp2WqL9xVb3HjT"
	if e := entropy.Shannon(above); e < 3.0 {
		t.Fatalf("above-floor fixture entropy = %v, want >= 3.0", e)
	}
	t.Run("above_three_reported", func(t *testing.T) {
		content := `{"password":"` + above + `"}`
		if n := countRule(ScanJSONFile("app.json", content, rs, finding.SeverityLow), heuristicRule); n != 1 {
			t.Fatalf("entropy %.4f at or above the heuristic's 3.0 floor: expected 1 finding, got %d",
				entropy.Shannon(above), n)
		}
	})
}

// TestJSONKeyNameHeuristicFloorIsExactlyThreeNotRuleEntropyFloor is the
// tripwire for the `e >= 3.0` at scanner.go:75. Unlike
// TestJSONKeyNameHeuristicFloorUnaffected above — which pins the floor only to
// within the loose (2.5, 3.5] window its two fixtures happen to bracket — this
// test pins the floor's VALUE to the interval (2.999, 3.0], so nudging the
// literal in either direction fails here.
//
// WHY IT IS DELIBERATELY NOT decoder.RuleEntropyFloor: that branch fires on
// `secretKeyRE.MatchString(keyName)`, which is a match on a JSON KEY NAME, not
// on a rule. There is no `rule` in scope to read an entropy_threshold from —
// the nearest `rule` variable belongs to the sibling ruleset loop further down
// the function, which does not execute when secretKeyRE matches. The only
// value `RuleEntropyFloor` can return without a rule is `RuleEntropyFloor(0)`
// == 2.0, so "unifying" the two gates is not a refactor, it is a silent
// lowering of this one from 3.0 to 2.0 that re-admits every value in
// [2.0, 3.0) under a `json_<keyName>` rule name. The literal is the correct
// way to say "this threshold belongs to a heuristic, not to a rule".
func TestJSONKeyNameHeuristicFloorIsExactlyThreeNotRuleEntropyFloor(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	const heuristicRule = "json_password"

	// Premise guard: a rule-less RuleEntropyFloor call must NOT be able to
	// express 3.0, or the "deliberately literal" argument above is void. This
	// also fails loudly if someone raises the global default in
	// decoder/pipeline.go, which would silently change this branch's meaning.
	if got := decoder.RuleEntropyFloor(0); got >= 3.0 {
		t.Fatalf("decoder.RuleEntropyFloor(0) = %v, want < 3.0: this test's premise is that "+
			"no rule-less call can produce the heuristic's 3.0 floor, so scanner.go's "+
			"literal must stay literal", got)
	}

	// Just under 3.0: 8 symbols, counts {9,8,8,8,8,8,8,8} over "abcdefgh".
	// Measured 2.999000 — suppressed, so the floor is strictly above 2.999.
	belowFloor := "aaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhh"
	belowE := entropy.Shannon(belowFloor)
	if belowE <= 2.99 || belowE >= 3.0 {
		t.Fatalf("just-under fixture entropy = %.6f, want in (2.99, 3.0); the fixture drifted", belowE)
	}
	t.Run("just_under_three_suppressed", func(t *testing.T) {
		content := `{"password":"` + belowFloor + `"}`
		if n := countRule(ScanJSONFile("app.json", content, rs, finding.SeverityLow), heuristicRule); n != 0 {
			t.Fatalf("entropy %.6f is just under 3.0: the heuristic floor is no longer pinned at "+
				"3.0 (it can only be <= %.6f now); got %d %s findings", belowE, belowE, n, heuristicRule)
		}
	})

	// Exactly 3.0: 8 distinct symbols, one of each. Measured 3.000000 — and the
	// comparison is `e >= 3.0`, so equality reports. This is the sharp edge: a
	// floor nudged to 3.0000001 suppresses it and fails here.
	atFloor := "abcdefgh"
	atE := entropy.Shannon(atFloor)
	if atE != 3.0 {
		t.Fatalf("at-floor fixture entropy = %.6f, want exactly 3.0; the fixture drifted", atE)
	}
	t.Run("exactly_three_reported", func(t *testing.T) {
		content := `{"password":"` + atFloor + `"}`
		if n := countRule(ScanJSONFile("app.json", content, rs, finding.SeverityLow), heuristicRule); n != 1 {
			t.Fatalf("entropy %.6f == 3.0 and the comparison is `e >= 3.0`: the heuristic floor is no "+
				"longer pinned at 3.0 (it must be <= 3.0); got %d %s findings", atE, n, heuristicRule)
		}
	})
}
