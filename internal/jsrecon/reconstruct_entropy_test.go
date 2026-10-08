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

// TestReconstructEntropyFloorHonorsRuleThreshold guards reconstruct.go:412.
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
// change: env_generic_secret really does carry a 3.0 entropy_threshold, and it
// is the only rule that does.
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
		t.Errorf("%d rules carry an entropy_threshold, want exactly 1 (env_generic_secret)", thresholds)
	}
}
