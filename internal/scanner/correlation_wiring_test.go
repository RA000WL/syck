package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// fullCorrelator registers every detector internal/correlation ships. It is a
// mirror of the production set: NewPipeline currently hands CorrelationStage a
// bare correlator with no detectors registered at all, so a stage-level test has
// to build one to see any correlation output.
func fullCorrelator() *correlation.Correlator {
	c := correlation.NewCorrelator()
	c.RegisterDetector(correlation.AWSDetector{})
	c.RegisterDetector(correlation.StripeDetector{})
	c.RegisterDetector(correlation.TwilioDetector{})
	c.RegisterDetector(correlation.CloudflareDetector{})
	c.RegisterDetector(correlation.GitHubAppDetector{})
	c.RegisterDetector(correlation.JWTKeyDetector{})
	c.RegisterDetector(correlation.OAuthDetector{})
	c.RegisterDetector(correlation.DatabaseURLDetector{})
	return c
}

// awsPair is the two-component AWS credential pair on one line span, using the
// access key id and secret access key from AWS's own documentation.
func awsPair(lineA, lineB int) []finding.Finding {
	return []finding.Finding{
		{
			RuleName:       "aws_access_key_id",
			File:           "aws.txt",
			Line:           lineA,
			Column:         20,
			Severity:       finding.SeverityCritical,
			Secret:         "AKIAIOSFODNN7EXAMPLE",
			Context:        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			Confidence:     confidence.PtsRegex,
			ConfidenceBand: confidence.Band(confidence.PtsRegex),
		},
		{
			RuleName:       "aws_secret_access_key",
			File:           "aws.txt",
			Line:           lineB,
			Severity:       finding.SeverityCritical,
			Secret:         `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			Context:        `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			Confidence:     confidence.PtsRegex,
			ConfidenceBand: confidence.Band(confidence.PtsRegex),
		},
	}
}

func correlated(lines []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range lines {
		if f.RuleName == "aws_credential_pair" || f.RuleName == "stripe_credential_pair" ||
			f.RuleName == "twilio_credential_pair" || f.RuleName == "database_url_with_credentials" {
			out = append(out, f)
		}
	}
	return out
}

// TestCorrelationStageEmitsAShape pins what CorrelationStage.Process actually
// produces today for a credential pair. Every field below is asserted at its
// real value so the three defects are on record rather than described.
func TestCorrelationStageEmitsAShape(t *testing.T) {
	s := NewCorrelationStage(fullCorrelator())
	got := s.Process(awsPair(1, 2))

	if len(got) != 3 {
		t.Fatalf("Process returned %d findings, want 3 (2 components + 1 pair)", len(got))
	}
	p := got[2]

	// Defect (a): no severity is derived, so the pair carries finding.Finding's
	// zero value — SeverityInfo (0) — even though both of its components are
	// CRITICAL. The CLI's default floor is --severity LOW (1).
	if p.Severity != finding.SeverityInfo {
		t.Errorf("Severity = %v, want %v (zero value: nothing derives it)", p.Severity, finding.SeverityInfo)
	}

	// Defect (c): matchPair stamps Confidence "VERY_HIGH", which is outside the
	// LOW/MEDIUM/HIGH/CRITICAL vocabulary confidence.Band can produce.
	if p.ConfidenceBand != "VERY_HIGH" {
		t.Errorf("ConfidenceBand = %q, want VERY_HIGH (matchPair's literal, passed through)", p.ConfidenceBand)
	}
	if p.Confidence != 0 {
		t.Errorf("Confidence = %d, want 0 (no score is derived either)", p.Confidence)
	}
	for _, band := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if p.ConfidenceBand == band {
			t.Errorf("ConfidenceBand %q is in-band — the defect this pins would be gone", band)
		}
	}

	if p.RuleName != "aws_credential_pair" {
		t.Errorf("RuleName = %q, want aws_credential_pair", p.RuleName)
	}
	// Secret is a description, not a secret: there is no matched value to show.
	wantSecret := "aws_access_key_id + aws_secret_access_key found within 1 lines"
	if p.Secret != wantSecret {
		t.Errorf("Secret = %q, want %q", p.Secret, wantSecret)
	}
	if p.Context != "aws_credential_pair" {
		t.Errorf("Context = %q, want aws_credential_pair (it duplicates RuleName)", p.Context)
	}
	if p.DetectionMethod != "" {
		t.Errorf("DetectionMethod = %q, want empty", p.DetectionMethod)
	}
	if p.File != "aws.txt" || p.Line != 1 {
		t.Errorf("position = %s:%d, want aws.txt:1 (component A's)", p.File, p.Line)
	}
}

// TestCorrelationStageIgnoresMinSeverity pins defect (b). MinSeverity is
// applied inside the scan paths (helpers.go:547 and the sub-scanner calls), not
// after collection, and CorrelationStage.Process takes no severity input at all
// — so a pair appended after collection cannot be filtered no matter what floor
// the scan was run at. Both components here are CRITICAL; the pair still comes
// out at SeverityInfo, below every floor the CLI can be run at.
func TestCorrelationStageIgnoresMinSeverity(t *testing.T) {
	// The CLI's default floor is LOW, so the bypass bites on every floor the
	// flag can actually be set to. INFO is excluded deliberately: at that floor
	// an INFO pair is not below it, so there is nothing to bypass.
	for _, floor := range []finding.Severity{
		finding.SeverityLow, finding.SeverityMedium,
		finding.SeverityHigh, finding.SeverityCritical,
	} {
		t.Run(finding.SeverityNames[floor], func(t *testing.T) {
			s := NewCorrelationStage(fullCorrelator())
			got := s.Process(awsPair(1, 2))

			var pair *finding.Finding
			for i := range got {
				if got[i].RuleName == "aws_credential_pair" {
					pair = &got[i]
				}
			}
			if pair == nil {
				t.Fatal("pair was not emitted at all — the bypass this pins would be gone")
			}
			if pair.Severity >= floor {
				t.Fatalf("pair severity %v meets floor %v — it would be filtered, so the bypass is gone",
					pair.Severity, floor)
			}
		})
	}
}

// TestConfidenceBandVocabulary pins the band vocabulary the fix has to use, so
// the off-band literal cannot be reintroduced silently.
func TestConfidenceBandVocabulary(t *testing.T) {
	inBand := map[string]bool{}
	for score := 0; score <= confidence.MaxScore; score++ {
		inBand[confidence.Band(score)] = true
	}
	if _, ok := inBand["VERY_HIGH"]; ok {
		t.Error("Band() produced VERY_HIGH for an in-range score; the vocabulary assumption is wrong")
	}
	for _, want := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		if !inBand[want] {
			t.Errorf("Band() never produced %q", want)
		}
	}
}

// TestDatabaseURLDetectorIsNotAPair documents what
// internal/correlation/detector_database_url.go actually is: a single-component
// detector that regex-matches finding.Secret, not a matchPair over two rule
// names. Its "components" are the one finding it fired on.
func TestDatabaseURLDetectorIsNotAPair(t *testing.T) {
	c := correlation.NewCorrelator()
	c.RegisterDetector(correlation.DatabaseURLDetector{})

	fs := []finding.Finding{
		{RuleName: "postgres_url", File: "db.txt", Line: 7, Secret: "postgres://app:s3cret@db.example.com:5432/app", Severity: finding.SeverityCritical},
		{RuleName: "google_api_key", File: "db.txt", Line: 9, Secret: "not-a-url"},
	}
	got := c.Correlate(fs)
	if len(got) != 1 {
		t.Fatalf("Correlate returned %d, want 1", len(got))
	}
	if got[0].Type != "database_url_with_credentials" {
		t.Errorf("Type = %q, want database_url_with_credentials", got[0].Type)
	}
	if len(got[0].Components) != 1 {
		t.Errorf("Components = %d, want 1 (single finding, no pair)", len(got[0].Components))
	}
	if got[0].Components[0].Line != 7 {
		t.Errorf("component line = %d, want 7", got[0].Components[0].Line)
	}
}

// TestComponentRulesExistForEachDetector records which detectors can fire at
// all. Every matchPair detector keys off two component rule names; a detector is
// dead unless both of those names exist in the default ruleset, because
// nothing on the scan path can then produce a component for it to match.
// Adding the missing rule sets is deliberately out of scope for this batch.
func TestComponentRulesExistForEachDetector(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	inRuleset := map[string]bool{}
	for _, r := range rs.Rules {
		inRuleset[r.Name] = true
	}

	cases := []struct {
		detector string
		a, b     string
	}{
		{"AWSDetector", "aws_access_key_id", "aws_secret_access_key"},
		{"StripeDetector", "stripe_secret_key", "stripe_publishable_key"},
		{"TwilioDetector", "twilio_account_sid", "twilio_auth_token"},
		{"CloudflareDetector", "cloudflare_email", "cloudflare_api_key"},
		{"GitHubAppDetector", "github_app_id", "github_app_private_key"},
		{"JWTKeyDetector", "jwt", "jwt_signing_key"},
		{"OAuthDetector", "oauth_client_id", "oauth_client_secret"},
	}

	var live, dead []string
	for _, tc := range cases {
		hasA, hasB := inRuleset[tc.a], inRuleset[tc.b]
		switch {
		case hasA && hasB:
			live = append(live, tc.detector)
		case !hasA && !hasB:
			dead = append(dead, tc.detector+" (neither "+tc.a+" nor "+tc.b+" exists)")
		default:
			t.Errorf("%s is half-dead: %s exists=%v, %s exists=%v", tc.detector, tc.a, hasA, tc.b, hasB)
		}
	}

	if len(live) != 3 {
		t.Errorf("live detectors = %v, want 3", live)
	}
	if len(dead) != 4 {
		t.Errorf("dead detectors = %v, want 4", dead)
	}
	t.Logf("live: %v", live)
	t.Logf("dead: %v", dead)
}

// The five cases below are the spec's characterization set, run through the
// real V6 entry point (ScanPaths) against the real default ruleset.
const fixtureAWSInSpan = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
	"aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"

func scanFixture(t *testing.T, cfg Config, files map[string]string) []finding.Finding {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Rules = rs
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ScanPaths([]string{root}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestCorrelationWiringCase1_PairInSpan(t *testing.T) {
	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": fixtureAWSInSpan}))
	if len(got) != 0 {
		t.Fatalf("got %d correlated findings, want 0", len(got))
	}
}

func TestCorrelationWiringCase2_PairBeyondSpan(t *testing.T) {
	body := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
	for i := 0; i < 25; i++ {
		body += "// filler\n"
	}
	body += "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"

	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": body}))
	if len(got) != 0 {
		t.Fatalf("got %d correlated findings, want 0", len(got))
	}
}

func TestCorrelationWiringCase3_SingleComponent(t *testing.T) {
	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"}))
	if len(got) != 0 {
		t.Fatalf("got %d correlated findings, want 0", len(got))
	}
}

func TestCorrelationWiringCase4_MinSeverityStillFilters(t *testing.T) {
	// A fixture in a "fixtures" directory is one that DowngradeFP already lowers
	// by one severity, which is the only way to get a live pair below the
	// CRITICAL floor under the current ruleset.
	for _, tc := range []struct {
		name string
		min  finding.Severity
	}{
		{"critical floor", finding.SeverityCritical},
		{"high floor", finding.SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := correlated(scanFixture(t, Config{MinSeverity: tc.min, DowngradeFP: true},
				map[string]string{"fixtures/aws.txt": fixtureAWSInSpan}))
			if len(got) != 0 {
				t.Fatalf("got %d correlated findings, want 0", len(got))
			}
		})
	}
}

func TestCorrelationWiringCase5_NoCorrelation(t *testing.T) {
	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": fixtureAWSInSpan}))
	if len(got) != 0 {
		t.Fatalf("got %d correlated findings, want 0", len(got))
	}
}
