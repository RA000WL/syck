package jsrecon

import (
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Characterization of the hardcoded global entropy floor at reconstruct.go:411
// (`if e < 2.0`), against env_generic_secret — the only rule in
// internal/rules/builtin.yaml carrying an `entropy_threshold` (3.0).
//
// WHAT `e` IS COMPUTED OVER. `scanReconstructed` calls `rule.MatchAll`, which
// wraps `regexp.FindAllStringIndex` and therefore returns only [start, end] of
// the *whole* match — there are no submatch indices. env_generic_secret's
// pattern
//
//	(?:^|\s)(?:\w+_SECRET=\S{8,}|\w+_PASSWORD=\S{8,}|\w+_TOKEN=\S{20,}|\w+_API_KEY=\S{20,})
//
// contains no capturing group (verified: FindAllStringSubmatch returns exactly
// 1 element, the full match). So `secret = reconstructed[m[0]:m[1]]` is the whole
// `KEY=value` string, NOT just the value. Measured with entropy.Shannon:
//
//	lowSecret  "MY_SECRET=aaaaaaaazzzzzzzzzzzzzzzzzzzz"  Shannon = 2.2890  → in [2.0, 3.0)
//	highSecret "MY_SECRET=kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO" Shannon = 5.0280  → above 3.0
//
// For contrast, the value sub-span alone scores far lower
// ("aaaaaaaa" = 0.0000), so the 3.0 floor is largely satisfied by the key name.
const (
	reconLowSecret  = "MY_SECRET=aaaaaaaazzzzzzzzzzzzzzzzzzzz"
	reconHighSecret = "MY_SECRET=kR7mZp2WqL9xVb3HjTQ2wE8rT5yU1iO"
)

// requireReconEntropyBands pins the fixture measurements above. If the
// assertions below are to mean anything, these fixtures must keep straddling
// the 2.0 hardcoded floor and the 3.0 rule threshold.
func requireReconEntropyBands(t *testing.T) {
	t.Helper()
	if e := entropy.Shannon(reconLowSecret); e < 2.0 || e >= 3.0 {
		t.Fatalf("reconLowSecret entropy = %v, want [2.0, 3.0)", e)
	}
	if e := entropy.Shannon(reconHighSecret); e <= 3.0 {
		t.Fatalf("reconHighSecret entropy = %v, want > 3.0", e)
	}
}

// jsReconstructedTo builds JS that propagates two string constants into a
// concatenation, so the reconstructed text is exactly `want`.
func jsReconstructedTo(want string) string {
	half := len(want) / 2
	return "var a = \"" + want[:half] + "\";\n" +
		"var b = \"" + want[half:] + "\";\n" +
		"var assembled = a + b;\n"
}

// reconEnvGenericFindings returns the findings this package attributes to
// env_generic_secret. scanReconstructed prefixes the rule name with the
// detection tag, so match on the suffix rather than an exact name.
func reconEnvGenericFindings(findings []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range findings {
		if strings.HasSuffix(f.RuleName, "env_generic_secret") {
			out = append(out, f)
		}
	}
	return out
}

func containsSecret(findings []finding.Finding, want string) bool {
	for _, f := range findings {
		if f.Secret == want {
			return true
		}
	}
	return false
}

// TestReconstructEntropyFloorHonorsRuleThreshold guards reconstruct.go:416.
// Before this gate consulted decoder.RuleEntropyFloor(rule.EntropyThreshold),
// every rule here got the hardcoded global 2.0 floor, so a match in [2.0, 3.0)
// was reported from reconstructed JS even though env_generic_secret's own 3.0
// threshold suppresses it on the plain-file path. That disagreement is the bug;
// the subtests below pin the fixed behavior in both directions.
func TestReconstructEntropyFloorHonorsRuleThreshold(t *testing.T) {
	requireReconEntropyBands(t)
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	t.Run("low_entropy_suppressed_by_rule_threshold", func(t *testing.T) {
		got := ReconstructAndScan(jsReconstructedTo(reconLowSecret), "app.js", rs, finding.SeverityLow)
		if containsSecret(reconEnvGenericFindings(got), reconLowSecret) {
			t.Fatalf("entropy %.4f under env_generic_secret's 3.0 threshold: expected suppression, got %+v",
				entropy.Shannon(reconLowSecret), got)
		}
	})

	t.Run("high_entropy_reported", func(t *testing.T) {
		got := ReconstructAndScan(jsReconstructedTo(reconHighSecret), "app.js", rs, finding.SeverityLow)
		if !containsSecret(reconEnvGenericFindings(got), reconHighSecret) {
			t.Fatalf("entropy %.4f above 3.0: expected a finding; got %+v",
				entropy.Shannon(reconHighSecret), got)
		}
	})
}

// TestReconstructEnvGenericThresholdIsThree pins the premise of the whole
// change: env_generic_secret really does carry a 3.0 entropy_threshold, and at
// the time of writing it is the only rule that does.
//
// The "only one rule" half is a blast-radius tripwire, not a correctness
// assertion — a second threshold is a legitimate ruleset change and the failure
// message below says so. The "3.0" half is a real assertion.
func TestReconstructEnvGenericThresholdIsThree(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	thresholds := 0
	found := false
	for i := range rs.Rules {
		if rs.Rules[i].EntropyThreshold > 0 {
			thresholds++
		}
		if rs.Rules[i].Name == "env_generic_secret" {
			found = true
			if rs.Rules[i].EntropyThreshold != 3.0 {
				t.Errorf("env_generic_secret EntropyThreshold = %v, want 3.0", rs.Rules[i].EntropyThreshold)
			}
		}
	}
	if !found {
		t.Fatal("env_generic_secret not present in the default ruleset")
	}
	if thresholds != 1 {
		// Not necessarily a defect: adding a threshold to a second rule is a
		// legitimate ruleset change. It is only a review trigger — that rule's
		// floor now moves on ALL paths at once, so ARCHITECTURE.md §15 item 6
		// and this branch's blast-radius claims must be re-read before shipping.
		t.Errorf("REVIEW REQUIRED: %d rules carry an entropy_threshold (expected 1, env_generic_secret). "+
			"A new threshold widens this batch's blast radius beyond the one rule claimed in CHANGELOG.md; "+
			"update the CHANGELOG table, ARCHITECTURE.md §15 item 6, and this file's measured fixtures, "+
			"or remove the threshold if it was not intentional", thresholds)
	}
}

// TestReconstructThresholdlessRuleKeepsGlobalFloor is the negative control for
// the change above, in the direction the env_generic_secret tests cannot cover.
//
// env_generic_secret is the ONE rule carrying an entropy_threshold, so both
// subtests above pass whether the code calls decoder.RuleEntropyFloor or reads
// rule.EntropyThreshold directly — for that rule the two are indistinguishable.
// They differ for the other ~90 rules: RuleEntropyFloor(0) returns the global
// 2.0, while rule.EntropyThreshold is 0. So a regression that dropped the
// helper and read the threshold directly would leave every threshold-less rule
// with no floor at all and start reporting sub-2.0 spans, and no other test in
// this file would fail.
//
// aws_access_key_id is threshold-less and has no requires_context, so it is
// driven here without a context keyword. Measured: Shannon("AKIAAAAAAAAAAAAAAAAA")
// = 0.5690, far below the global 2.0 floor, so it is suppressed. Under the
// broken form the comparison becomes 0.5690 < 0 — false — and the finding would
// be reported, failing this test.
//
// Verified by mutation: replacing RuleEntropyFloor's body with `return th`
// makes this test fail. Without that check the assertion would be vacuous —
// an earlier draft of this fixture used a string that produced no finding under
// any configuration, so it passed regardless.
func TestReconstructThresholdlessRuleKeepsGlobalFloor(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	var saw bool
	for _, r := range rs.Rules {
		if r.Name != "aws_access_key_id" {
			continue
		}
		saw = true
		if r.EntropyThreshold != 0 {
			t.Fatalf("fixture assumes aws_access_key_id is threshold-less, got %v", r.EntropyThreshold)
		}
		if r.RequiresContext {
			t.Fatal("fixture assumes aws_access_key_id has no requires_context")
		}
	}
	if !saw {
		t.Fatal("fixture rule aws_access_key_id is gone from the default ruleset")
	}

	const subFloor = "AKIAAAAAAAAAAAAAAAAA" // Shannon = 0.5690
	if e := entropy.Shannon(subFloor); e >= 2.0 {
		t.Fatalf("fixture %q scores %.4f, which is not below the 2.0 global floor", subFloor, e)
	}

	for _, f := range ReconstructAndScan(jsReconstructedTo(subFloor), "app.js", rs, finding.SeverityLow) {
		if strings.Contains(f.Secret, "AKIA") {
			t.Fatalf("threshold-less rule match at entropy %.4f must stay suppressed by the global 2.0 floor; "+
				"got a finding — the decoder.RuleEntropyFloor call was likely replaced by a bare "+
				"rule.EntropyThreshold read, which would drop the floor for every rule without one: %+v",
				entropy.Shannon(subFloor), f)
		}
	}
}
