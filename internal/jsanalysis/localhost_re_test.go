package jsanalysis

import (
	"slices"
	"testing"
)

// TestLocalhostRE_SixInputs pins the six inputs that defined Batch 10
// (docs/superpowers/specs/2026-10-05-syck-batch10-localhostre-design.md section
// 5). Every row is asserted as the WHOLE InternalURLs slice, so a row that
// starts reporting more — or different — findings fails rather than passing
// silently on a "contains" check.
//
// Batch 10 landed with these expectations; the before-picture they replaced is
// kept in the table in each row's comment, so the direction of travel stays
// readable without consulting git:
//
//	| Input                        | Before            | After               |
//	|------------------------------|-------------------|---------------------|
//	| http://my-localhost:8080/    | localhost:8080    | my-localhost:8080   |
//	| LOCALHOST:8080               | (nothing)         | LOCALHOST:8080      |
//	| 127.0.0.2:8080               | (nothing)         | 127.0.0.2:8080      |
//	| [::1]:8080                   | (nothing)         | [::1]:8080          |
//	| localhost:8080               | localhost:8080    | localhost:8080      |
//	| example.com:8080             | (nothing)         | (nothing)           |
//
// The first row is the anchoring fix and is the one users keying on the emitted
// substring will see move. Rows 2-4 are the vocabulary widening.
//
// Only localhostRE contributes to InternalURLs on these lines. internalServiceRE
// needs an internal/private/corp/intranet/staging/dev/sandbox/test keyword
// followed by ":" or "=", and configURLRE needs a baseURL/apiURL/api_url/
// endpoint/baseUrl/host/server/origin keyword followed by ":" or "=" — "db" and
// "api" are neither, so the two existing InternalURLs producers stay out.
func TestLocalhostRE_SixInputs(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string // full InternalURLs slice, in order
	}{
		{
			// Was "localhost:8080" — the carved subspan. Now the whole host
			// the author typed, because the match is anchored at a host-token
			// boundary and consumes the preceding labels.
			name: "loopback token inside a longer host reports the whole host",
			line: `var api = "http://my-localhost:8080/api";`,
			want: []string{"my-localhost:8080"},
		},
		{
			// Was nothing — case-sensitive.
			name: "uppercase spelling is matched",
			line: `var db = "LOCALHOST:8080";`,
			want: []string{"LOCALHOST:8080"},
		},
		{
			// Was nothing — 127.0.0.1 only, not 127/8.
			name: "127/8 beyond 127.0.0.1 is matched",
			line: `var db = "127.0.0.2:8080";`,
			want: []string{"127.0.0.2:8080"},
		},
		{
			// Was nothing — no IPv6 rule at all.
			name: "bracketed IPv6 loopback is matched",
			line: `var db = "[::1]:8080";`,
			want: []string{"[::1]:8080"},
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

// TestLocalhostRE_AnchoringBounds pins where the anchoring draws its lines. The
// boundary is a character class, not \b: "-" and "." are non-word characters, so
// \b would still match at the seam in "my-localhost" and "foo.localhost" and the
// carve-up Batch 10 removed would come straight back.
func TestLocalhostRE_AnchoringBounds(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			// A label separator, so the whole hosts is reported.
			name: "hyphen-joined host reports whole",
			line: `var api = "http://my-localhost:8080/api";`,
			want: []string{"my-localhost:8080"},
		},
		{
			name: "dotted host reports whole",
			line: `var api = "http://foo.localhost:8080/api";`,
			want: []string{"foo.localhost:8080"},
		},
		{
			name: "multi-label host reports whole",
			line: `var api = "http://a.b-c.localhost:8080/api";`,
			want: []string{"a.b-c.localhost:8080"},
		},
		{
			// A leading separator is still part of the token the author typed
			// (cookie-domain and root-zone spellings both use it), so the
			// finding is kept and now carries the dot rather than being
			// carved. Without allowing a bare separator in the prefix group
			// this class would lose its finding entirely.
			name: "leading-dot host reports whole",
			line: `var api = "http://.localhost:8080/api";`,
			want: []string{".localhost:8080"},
		},
		{
			// No separator: "localhost" is glued to the front of the label, so
			// the token is not the final label of a host and nothing matches.
			// This is what keeps the anchor from re-introducing the carve-up.
			name: "token glued to the front of a label does not match",
			line: `var api = "http://localhostX:8080/api";`,
			want: nil,
		},
		{
			name: "token with a prefix and no separator does not match",
			line: `var api = "http://notlocalhost:8080/api";`,
			want: nil,
		},
		{
			// Not the final label of its host: the loopback label starts the
			// hostname and the public label ends it, so the whole host is
			// "localhost.example.com" and it is not loopback. The old
			// unanchored regex emitted the subspan "localhost:8080" here.
			name: "loopback token that is not the final label does not match",
			line: `var api = "http://localhost.example.com:8080/api";`,
			want: nil,
		},
		{
			// The one class the anchoring genuinely removes: a token glued to
			// the FRONT of a label is not a host at all, so reporting it was a
			// false positive. It used to emit the subspan "localhost:8080".
			name: "token glued to a label is not carved out",
			line: `var api = "http://notlocalhost:8080/api";`,
			want: nil,
		},
		{
			// A loopback token inside a PATH is still a finding: the extractor
			// reads raw text, not a parsed URL, so a token it can see it
			// reports. Boundary before "/" is what fires here.
			name: "loopback token in a path still reports the whole host",
			line: `var api = "http://example.com/redirect/my-localhost:8080";`,
			want: []string{"my-localhost:8080"},
		},
		{
			// Not a host-shaped token at all.
			name: "invalid octet does not match",
			line: `var api = "http://127.300.1.1:8080/api";`,
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

// TestLocalhostRE_VocabularyBounds pins the widened vocabulary and the part of
// the port requirement that did not move. The :port requirement is deliberate:
// it is what makes this a service-address finding rather than a bare hostname,
// which is the boundary between this extractor and internalurl.IsLoopback.
func TestLocalhostRE_VocabularyBounds(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "all of 127/8 as dotted quads is matched",
			line: `var a = "127.0.0.0:8080", b = "127.0.0.255:3000", c = "127.255.255.254:9000";`,
			want: []string{"127.0.0.0:8080", "127.0.0.255:3000", "127.255.255.254:9000"},
		},
		{
			name: "the unspecified address is matched",
			line: `var listen = "0.0.0.0:9000";`,
			want: []string{"0.0.0.0:9000"},
		},
		{
			name: "bracketed ::1 is matched inside a URL",
			line: `var api = "http://[::1]:8080/api";`,
			want: []string{"[::1]:8080"},
		},
		{
			// Still out: the port shape and the port requirement are unchanged
			// by the widening.
			name: "portless host is not matched",
			line: `var api = "http://127.0.0.1/api";`,
			want: nil,
		},
		{
			name: "bare localhost name is not matched",
			line: `if (window.location.hostname === "localhost") { fetch("/x") }`,
			want: nil,
		},
		{
			// IsLoopback accepts this and this extractor still does not: no port.
			name: "portless bracketed IPv6 is not matched",
			line: `var api = "http://[::1]/api";`,
			want: nil,
		},
		{
			// A leading-zero spelling is not a dotted quad this pattern accepts.
			name: "leading-zero octet does not match",
			line: `var api = "http://127.0.0.01:8080/api";`,
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

// TestLocalhostRE_UnchangedShapes pins the neighbouring shapes the fix leaves
// alone: the three spellings the regex already knew, a host:port on a public
// hostname, and both portless forms. Together with
// TestLocalhostRE_SixInputs this is the whole blast radius of Batch 10.
func TestLocalhostRE_UnchangedShapes(t *testing.T) {
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
			// Two tokens on one line, each found separately: the boundary
			// character before the second is not consumed by the first match.
			name: "adjacent tokens on one line are both found",
			line: `var all = "localhost:8080 127.0.0.1:3000";`,
			want: []string{"localhost:8080", "127.0.0.1:3000"},
		},
		{
			// The port requirement is what makes this a service-address
			// finding; a portless host is out of scope and stays out.
			name: "portless host is not matched",
			line: `var api = "http://127.0.0.1/api";`,
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
