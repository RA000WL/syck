package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

// TestDowngradeFPChecksSecretNotContext is the regression pin for the
// placeholder demotion testing the wrong string.
//
// DowngradeFP demoted a finding to INFO when the placeholder regex matched the
// finding's CONTEXT — which is the whole source line. So any unrelated use of
// the word "example" anywhere on that line wiped a live key to INFO, below the
// default --severity floor:
//
//	const cfg = { apiKey: "sk_live_…", example: "https://example.com/docs" };
//
// reported that Stripe key at INFO. The demotion is meant to say "the matched
// value is itself a placeholder", which is a property of the secret, and
// `DB_PASSWORD=changeme` still demotes because the match carries `changeme`
// with it.
//
// The directory-based step in DowngradeFP is deliberately untouched: a key in a
// test/ or fixtures/ directory really is less likely to be production, so that
// demotion is defensible. This one was not.
func TestDowngradeFPChecksSecretNotContext(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		context string
		want    finding.Severity
	}{
		{
			// The bug: a live key on a line that mentions "example".
			name:    "live_key_beside_the_word_example",
			secret:  "sk_live_51H8xQ2eZvKYlo2CrealLiveSecretValue123",
			context: `const cfg = { apiKey: "sk_live_51H8xQ2eZvKYlo2CrealLiveSecretValue123", example: "https://example.com/docs" };`,
			want:    finding.SeverityCritical,
		},
		{
			// "sample" and "dummy" are the same trap. The input severity is
			// CRITICAL and nothing legitimately demotes it, so CRITICAL is the
			// expected value — an earlier draft of this table said HIGH, having
			// conflated the input with a different rule's severity.
			name:    "live_key_beside_sample_and_dummy",
			secret:  "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
			context: `// sample payload for the dummy repo\ntoken := "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"`,
			want:    finding.SeverityCritical,
		},
		{
			// The behaviour the check exists for must keep working: the
			// matched value is itself a placeholder.
			name:    "placeholder_value_demotes",
			secret:  "DB_PASSWORD=changeme",
			context: "DB_PASSWORD=changeme",
			want:    finding.SeverityInfo,
		},
		{
			// Recorded for the gap it exposes rather than deleted: the regex's
			// alternative is `your[-_](?:key|secret|token|password)`, which
			// matches `your_key` but NOT `your_api_key` — the `api` segment
			// breaks it. So a real-looking `API_TOKEN=your_api_key` survives.
			// That is a pre-existing hole in the placeholder vocabulary, not
			// something this change introduced, and widening it is a separate
			// decision; pinning the current behaviour keeps it visible.
			name:    "your_api_key_value_survives_vocabulary_gap",
			secret:  "API_TOKEN=your_api_key",
			context: "API_TOKEN=your_api_key",
			want:    finding.SeverityCritical,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := []finding.Finding{{
				File: "svc.js", Line: 1, RuleName: "stripe_secret_key",
				Severity: finding.SeverityCritical,
				Secret:   tc.secret, Context: tc.context,
			}}
			got := DowngradeFP(in)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
			if got[0].Severity != tc.want {
				t.Errorf("severity = %v, want %v", got[0].Severity, tc.want)
			}
		})
	}
}

// TestDowngradeFPDirectoryStillDemotes pins the half of DowngradeFP that was
// already correct, so narrowing the placeholder check cannot be mistaken for
// removing the whole feature.
func TestDowngradeFPDirectoryStillDemotes(t *testing.T) {
	in := []finding.Finding{{
		File: "test/fixtures/creds.env", Line: 1, RuleName: "aws_access_key_id",
		// A real-looking secret, no placeholder in it — the directory is the
		// only signal, and it must still be honoured.
		Secret: "AKIAIOSFODNN7REALSECRET01", Context: "AKIAIOSFODNN7REALSECRET01",
		Severity: finding.SeverityCritical,
	}}
	got := DowngradeFP(in)
	if got[0].Severity >= finding.SeverityCritical {
		t.Errorf("severity = %v, want demoted below CRITICAL for a test/ path", got[0].Severity)
	}
}
