package jsanalysis

import (
	"slices"
	"testing"
)

// TestLocalhostRE_SixInputs_Characterization pins the six inputs that define
// Batch 10 against the UNMODIFIED extractor, before the vocabulary/anchoring
// fix lands. They are the contract in
// docs/superpowers/specs/2026-10-05-syck-batch10-localhostre-design.md section 5;
// every row is asserted as the WHOLE InternalURLs slice, so a row that starts
// reporting more (or different) findings fails rather than passing silently on
// a "contains" check.
//
// Only localhostRE contributes to InternalURLs on these lines. internalServiceRE
// needs an internal/private/corp/intranet/staging/dev/sandbox/test keyword
// followed by ":" or "=", and configURLRE needs a baseURL/apiURL/api_url/
// endpoint/baseUrl/host/server/origin keyword followed by ":" or "=" — "db" and
// "api" are neither, so the two existing InternalURLs producers stay out.
//
// Expected here is TODAY's behaviour, defect included: the first row is the
// unanchored subspan carve-up (the finding is "localhost:8080", a string that
// is not a host), rows 2-4 are the three under-matched classes that report
// nothing at all, and rows 5-6 must not move.
//
// Batch 10 rewrites these expectations; that rewrite is the change under test.
func TestLocalhostRE_SixInputs_Characterization(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string // full InternalURLs slice, in order
	}{
		{
			// The defect: the regex is unanchored, so the finding is the
			// carved SUBSPAN "localhost:8080" rather than the host typed.
			name: "loopback token inside a longer host is carved into a subspan",
			line: `var api = "http://my-localhost:8080/api";`,
			want: []string{"localhost:8080"},
		},
		{
			name: "uppercase spelling is not matched",
			line: `var db = "LOCALHOST:8080";`,
			want: nil,
		},
		{
			name: "127/8 beyond 127.0.0.1 is not matched",
			line: `var db = "127.0.0.2:8080";`,
			want: nil,
		},
		{
			name: "bracketed IPv6 loopback is not matched",
			line: `var db = "[::1]:8080";`,
			want: nil,
		},
		{
			// The one row that must survive the fix byte-for-byte.
			name: "plain localhost with a port is matched",
			line: `var db = "localhost:8080";`,
			want: []string{"localhost:8080"},
		},
		{
			// The negative that must also survive the fix.
			name: "non-loopback host with a port is not matched",
			line: `var db = "example.com:8080";`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeJS(tt.line, "config.js").InternalURLs
			if !slices.Equal(got, tt.want) {
				t.Errorf("InternalURLs = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLocalhostRE_UnchangedShapes_Characterization pins the neighbouring shapes
// the fix must leave alone: the three spellings the regex already knows, the
// host:port on a public hostname, and the two portless forms. Together with
// TestLocalhostRE_SixInputs_Characterization this is the full before-picture of
// Batch 10's blast radius.
func TestLocalhostRE_UnchangedShapes_Characterization(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "the three known spellings, with a public hostname between them",
			line: `var db = "localhost:8080", cache = "127.0.0.1:3000", listen = "0.0.0.0:9000", cdn = "example.com:8080";`,
			want: []string{"localhost:8080", "127.0.0.1:3000", "0.0.0.0:9000"},
		},
		{
			name: "a public host:port in a URL produces nothing",
			line: `var api = "https://api.prod.example.com:443/v2";`,
			want: nil,
		},
		{
			// The :port requirement is what makes this a service-address
			// finding; a portless host is out of scope today and must stay out.
			name: "portless host is not matched",
			line: `var api = "http://127.0.0.1/api";`,
			want: nil,
		},
		{
			name: "bare localhost name is not matched",
			line: `if (window.location.hostname === "localhost") { fetch("/x") }`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeJS(tt.line, "config.js").InternalURLs
			if !slices.Equal(got, tt.want) {
				t.Errorf("InternalURLs = %q, want %q", got, tt.want)
			}
		})
	}
}
