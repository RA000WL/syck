package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// ctxTestBody is a deterministic, high-entropy alphanumeric body used to build
// short-prefix fixtures. Mixed case + digits keep Shannon entropy above the
// 2.0 scan floor and out of the base58/hex false-positive heuristics.
const ctxTestBody = "aB3xY9mQ2vR7tL5nH8kP4wD6zJ1sF0gB2cE5uIoM3xN6qW1"

// ctxToken builds "<prefix><bodyLen chars of ctxTestBody>".
func ctxToken(prefix string, bodyLen int) string {
	body := ctxTestBody
	for len(body) < bodyLen {
		body += ctxTestBody
	}
	return prefix + body[:bodyLen]
}

// TestPrefixClusterGating pins the short-prefix cluster tightening:
// context-gated rules (moonshot/runway/dropbox) fire only when their keyword
// appears on the matching line, while length-only rules (elevenlabs/mapbox)
// reject short bodies outright and still fire on long ones with no keyword.
func TestPrefixClusterGating(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow}

	fires := func(content, ruleName string) bool {
		for _, f := range ScanContent(content, "fixture.txt", cfg) {
			if f.RuleName == ruleName {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name    string
		content string
		rule    string
		want    bool
	}{
		// moonshot: keyword on the line fires; bare token is an accepted FN (pinned).
		{"moonshot_keyword_fires", "MOONSHOT_API_KEY=" + ctxToken("ms-", 24), "moonshot_api_key", true},
		{"moonshot_bare_silent", ctxToken("ms-", 24) + " token", "moonshot_api_key", false},
		// runway: same shape.
		{"runway_keyword_fires", "RUNWAY_API_KEY=" + ctxToken("rw-", 24), "runway_api_key", true},
		{"runway_bare_silent", ctxToken("rw-", 24) + " token", "runway_api_key", false},
		// dropbox: same shape.
		{"dropbox_keyword_fires", "DROPBOX_TOKEN=" + ctxToken("sl.", 24), "dropbox_api_token", true},
		{"dropbox_bare_silent", ctxToken("sl.", 24) + " token", "dropbox_api_token", false},
		// elevenlabs: length only, no context gate — 40 fires bare, 24 is under 32.
		{"elevenlabs_long_bare_fires", ctxToken("sk_", 40), "elevenlabs_api_key", true},
		{"elevenlabs_short_silent", ctxToken("sk_", 24), "elevenlabs_api_key", false},
		// mapbox: length only, no context gate — 40 fires bare, 24 is under 32.
		{"mapbox_long_bare_fires", ctxToken("sk.", 40), "mapbox_api_token", true},
		{"mapbox_short_silent", ctxToken("sk.", 24), "mapbox_api_token", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fires(tc.content, tc.rule)
			if got != tc.want {
				t.Fatalf("rule %q fired=%v, want %v (content: %q)", tc.rule, got, tc.want, tc.content)
			}
		})
	}
}
