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

// TestGenericShapeGating pins the generic-shape cluster (Batch 2b Task 3):
// rules whose pattern matches everyday shapes (Bearer prose, bare emails,
// numeric/hex paths, cloud IDs) fire only when their context keyword appears
// on the same line, and the two severity corrections land —
// terraform_state_secret CRITICAL→HIGH, credential_url HIGH→MEDIUM.
// The oracle_cloud_ocid rewrite must match real OCIDs (old pattern only
// matched redacted `...` docs).
func TestGenericShapeGating(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow}

	findingFor := func(content, ruleName string) (finding.Finding, bool) {
		for _, f := range ScanContent(content, "fixture.txt", cfg) {
			if f.RuleName == ruleName {
				return f, true
			}
		}
		return finding.Finding{}, false
	}
	fires := func(content, ruleName string) bool {
		_, ok := findingFor(content, ruleName)
		return ok
	}

	// Deterministic fixtures: 32 lowercase hex chars and a JWT-shaped token,
	// both well above the 2.0 entropy floor and out of the FP heuristics.
	const hex32 = "9f3c7a1e5b8d42f6c0a9e3b7d15f842c"
	authTok := ctxToken("", 32)
	jwtTok := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9." + hex32
	elasticID := ctxToken("", 44) + ":" + ctxToken("", 12)
	azureLineLong := "DefaultEndpointsProtocol=https;AccountName=prodstorage;AccountKey=" +
		ctxToken("", 68) + ";EndpointSuffix=core.windows.net"
	azureLineShort := "DefaultEndpointsProtocol=https;AccountName=prodstorage;AccountKey=" +
		ctxToken("", 20) + ";EndpointSuffix=core.windows.net"
	tfstateBare := `    "value": "ami-0f3a9c1e7b2d4568a0c2e4f1",`
	tfstateAttrs := `    "value": "ami-0f3a9c1e7b2d4568a0c2e4f1", "attributes": {`
	tfstateSensitive := `    "value": "ami-0f3a9c1e7b2d4568a0c2e4f1", "sensitive": true,`

	tests := []struct {
		name    string
		content string
		rule    string
		want    bool
	}{
		// basic_auth_header: "authorization" keyword required, external to the
		// Basic|Bearer match itself.
		{"basic_auth_prose_silent", "The gateway rejected the request: Bearer " + authTok, "basic_auth_header", false},
		{"basic_auth_keyword_fires", "Authorization: Bearer " + authTok, "basic_auth_header", true},
		// email_address: requires_context now enforced (keywords were parsed but dead).
		{"email_bare_silent", "user@example.com", "email_address", false},
		{"email_keyword_fires", "Contact support@example.com", "email_address", true},
		// asana_personal_token: numeric/hex path only fires with "asana" on the line.
		{"asana_bare_silent", "1/" + hex32, "asana_personal_token", false},
		{"asana_keyword_fires", "ASANA_TOKEN=1/" + hex32, "asana_personal_token", true},
		// oracle_cloud_ocid: rewritten pattern matches a real OCID (old pattern
		// required a literal "..." and never matched real IDs); the redacted
		// short shape keeps matching after the rewrite (pinned as-is).
		{"ocid_real_fires", "ocid1.compartment.oc1.." + hex32, "oracle_cloud_ocid", true},
		{"ocid_redacted_still_fires", "redacted ocid1.x.y...", "oracle_cloud_ocid", true},
		// terraform_state_secret: only "sensitive" discriminates; "attributes"
		// alone (present in every tfstate) no longer fires.
		{"tfstate_value_no_sensitive_silent", tfstateBare, "terraform_state_secret", false},
		{"tfstate_attributes_only_silent", tfstateAttrs, "terraform_state_secret", false},
		{"tfstate_sensitive_fires", tfstateSensitive, "terraform_state_secret", true},
		// kubernetes_kubeconfig_token: vacuous "token"/"user" keywords dropped;
		// a kubeconfig flow block carrying "users" on the match line fires.
		{"kubeconfig_token_bare_silent", "token: " + jwtTok, "kubernetes_kubeconfig_token", false},
		{"kubeconfig_block_fires", "users: [{name: admin, user: {token: " + jwtTok + "}}]", "kubernetes_kubeconfig_token", true},
		// elasticsearch_cloud_id: generic 40:10 shape gated on elastic keywords.
		{"elastic_cloud_id_bare_silent", elasticID, "elasticsearch_cloud_id", false},
		{"elastic_cloud_id_keyword_fires", "elasticsearch cloud_id: " + elasticID, "elasticsearch_cloud_id", true},
		// azure_connection_string: AccountKey minimum raised 6→32.
		{"azure_short_key_silent", azureLineShort, "azure_connection_string", false},
		{"azure_long_key_fires", azureLineLong, "azure_connection_string", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fires(tc.content, tc.rule)
			if got != tc.want {
				t.Fatalf("rule %q fired=%v, want %v (content: %q)", tc.rule, got, tc.want, tc.content)
			}
		})
	}

	// Severity corrections: HIGH (not CRITICAL) for tfstate with "sensitive",
	// MEDIUM (not HIGH) for any user:pass@host URL.
	t.Run("tfstate_sensitive_severity_high", func(t *testing.T) {
		f, ok := findingFor(tfstateSensitive, "terraform_state_secret")
		if !ok {
			t.Fatalf("terraform_state_secret did not fire on %q", tfstateSensitive)
		}
		if f.Severity != finding.SeverityHigh {
			t.Fatalf("terraform_state_secret severity = %v, want HIGH (not CRITICAL)", f.Severity)
		}
	})
	t.Run("credential_url_severity_medium", func(t *testing.T) {
		content := "db url https://admin:s3cret-pass@db.internal.example.com:5432/app"
		f, ok := findingFor(content, "credential_url")
		if !ok {
			t.Fatalf("credential_url did not fire on %q", content)
		}
		if f.Severity != finding.SeverityMedium {
			t.Fatalf("credential_url severity = %v, want MEDIUM (not HIGH)", f.Severity)
		}
	})
}

// TestAirtableGating pins the airtable_api_key context gate (Batch 2b final
// fix): the bare `key<17-char>` shape is far too generic to fire on its own,
// so the rule only reports when "airtable" appears on the matching line.
// The bare-token miss is an accepted false negative (pinned).
func TestAirtableGating(t *testing.T) {
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

	// key + 13 alnum + trailing digit = 17 chars, matching
	// \bkey[A-Za-z0-9]{13}[0-9]\b exactly; mixed case + digits clear the
	// 2.0 entropy floor so only the context gate can silence it.
	airtableTok := "key" + ctxTestBody[:13] + "8"

	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"airtable_keyword_fires", "AIRTABLE_API_KEY=" + airtableTok, true},
		{"airtable_bare_silent", airtableTok + " token", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fires(tc.content, "airtable_api_key")
			if got != tc.want {
				t.Fatalf("rule airtable_api_key fired=%v, want %v (content: %q)", got, tc.want, tc.content)
			}
		})
	}
}
