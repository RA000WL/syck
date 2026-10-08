package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/rules"
)

// Characterization of the entropy gate at url_secrets.go:40 (`if e < 2.0`).
//
// WHAT `e` IS COMPUTED OVER: the URL query parameter VALUE
// (`e := entropy.Shannon(val)`), where `val := params.Get(param)`. It is not a
// regex capture — there is no regex here at all.
//
// THIS PATH DOES NOT RUN THE RULESET, so it has no rule whose
// entropy_threshold could be read. Three facts pin that down:
//
//  1. `ExtractURLSecrets(line, path, lineno)` takes no `*rules.RuleSet` and
//     its only loop is over the package-level `urlSecretParams` map, a
//     hardcoded param-name → rule-NAME-STRING table.
//  2. The emitted names (url_access_token, url_token, url_api_key,
//     url_auth_token, url_jwt, url_bearer_token, url_key, url_secret) are not
//     rules in internal/rules/builtin.yaml at all — see
//     TestURLSecretsRuleNamesAreNotBuiltinRules.
//  3. `e` therefore cannot be a rule match, so there is no `rule.EntropyThreshold`
//     for it to honor.
//
// Consequence: env_generic_secret's 3.0 floor cannot reach this path, and the
// design spec's premise that this is one of "three rule-matching scan paths"
// is wrong for this file. These tests pin the gate that actually exists (a
// hardcoded 2.0 over the bare param value, plus a `len(val) >= 16` gate) so the
// floor's real shape stays visible.
//
// Measured with entropy.Shannon:
//
//	"aaaaaaaaaaaaaaaa"     Shannon = 0.0000  → below the 2.0 floor
//	"ZqZqWwWwWwWwXxXx"     Shannon = 2.5000  → above the floor, below 3.0
//	"kR7mZp2WqL9xVb3HjT"   Shannon = 4.1700  → well above
const (
	urlBelowFloor = "aaaaaaaaaaaaaaaa"
	urlInBand     = "ZqZqWwWwWwWwXxXx" // Shannon 2.5000 — in [2.0, 3.0)
	urlAboveFloor = "kR7mZp2WqL9xVb3HjT"
)

func requireURLEntropyBands(t *testing.T) {
	t.Helper()
	if e := entropy.Shannon(urlBelowFloor); e >= 2.0 {
		t.Fatalf("urlBelowFloor entropy = %v, want < 2.0", e)
	}
	if e := entropy.Shannon(urlInBand); e < 2.0 || e >= 3.0 {
		t.Fatalf("urlInBand entropy = %v, want [2.0, 3.0)", e)
	}
	if e := entropy.Shannon(urlAboveFloor); e <= 3.0 {
		t.Fatalf("urlAboveFloor entropy = %v, want > 3.0", e)
	}
}

// TestURLSecretsFloorHardcodedToTwo pins CURRENT behavior: url_secrets.go:40
// is a hardcoded global 2.0 floor, with no per-rule threshold to consult.
func TestURLSecretsFloorHardcodedToTwo(t *testing.T) {
	requireURLEntropyBands(t)

	t.Run("below_floor_suppressed", func(t *testing.T) {
		line := "fetch('https://api.example.com/v1?apikey=" + urlBelowFloor + "')"
		if got := ExtractURLSecrets(line, "app.js", 1); len(got) != 0 {
			t.Fatalf("entropy %.4f under the hardcoded 2.0 floor: expected 0 findings, got %d: %+v",
				entropy.Shannon(urlBelowFloor), len(got), got)
		}
	})

	t.Run("in_band_reported", func(t *testing.T) {
		line := "fetch('https://api.example.com/v1?secret=" + urlInBand + "')"
		got := ExtractURLSecrets(line, "app.js", 1)
		if len(got) != 1 {
			t.Fatalf("entropy %.4f above the hardcoded 2.0 floor: expected 1 finding, got %d: %+v",
				entropy.Shannon(urlInBand), len(got), got)
		}
		if got[0].RuleName != "url_secret" {
			t.Errorf("RuleName = %q, want url_secret", got[0].RuleName)
		}
		if got[0].Secret != urlInBand {
			t.Errorf("Secret = %q, want the bare param value %q", got[0].Secret, urlInBand)
		}
	})

	t.Run("above_floor_reported", func(t *testing.T) {
		line := "fetch('https://api.example.com/v1?token=" + urlAboveFloor + "')"
		got := ExtractURLSecrets(line, "app.js", 1)
		if len(got) != 1 {
			t.Fatalf("entropy %.4f above the hardcoded 2.0 floor: expected 1 finding, got %d: %+v",
				entropy.Shannon(urlAboveFloor), len(got), got)
		}
	})

	t.Run("shorter_than_16_chars_dropped_before_entropy", func(t *testing.T) {
		// `len(val) >= 16` is checked first, so short values never reach the
		// entropy gate. "kR7mZp2WqL9xVb3" is 4.3 bits — high entropy, still dropped.
		line := "fetch('https://api.example.com/v1?token=kR7mZp2WqL9xVb3')"
		if got := ExtractURLSecrets(line, "app.js", 1); len(got) != 0 {
			t.Fatalf("15-char param value must be dropped by the length gate; got %d: %+v", len(got), got)
		}
	})
}

// TestURLSecretsRuleNamesAreNotBuiltinRules pins the reason this path cannot
// honor a per-rule threshold: every name ExtractURLSecrets can emit is a
// synthetic heuristic label, not a rule in the ruleset. If one of these ever
// becomes a real rule, this test fails and the entropy gate needs revisiting.
func TestURLSecretsRuleNamesAreNotBuiltinRules(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}
	builtin := make(map[string]bool, len(rs.Rules))
	for i := range rs.Rules {
		builtin[rs.Rules[i].Name] = true
	}
	for ruleName := range urlSecretParams {
		if builtin[ruleName] {
			t.Errorf("urlSecretParams emits %q, which IS a builtin rule — the 2.0 floor at "+
				"url_secrets.go:40 can now be given that rule's entropy_threshold", ruleName)
		}
	}
}
