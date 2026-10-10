package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/correlation"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// awsPair is the two-component AWS credential pair, using the access key id and
// secret access key from AWS's own documentation.
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

// TestCorrelatedFindingShape pins the shape a credential pair now emits through
// CorrelationStage.Process. The predecessor of this test pinned the same call at
// its un-fixed values — SeverityInfo, Confidence 0, ConfidenceBand "VERY_HIGH",
// Context = RuleName, DetectionMethod "" — which is where the three defects were
// recorded. Every field below is either derived from the components or is
// documentation text, never the struct's zero value or matchPair's literal.
func TestCorrelatedFindingShape(t *testing.T) {
	s := NewCorrelationStage(newScanCorrelator(), finding.SeverityLow)
	got := s.Process(awsPair(1, 2))

	if len(got) != 3 {
		t.Fatalf("Process returned %d findings, want 3 (2 components + 1 pair)", len(got))
	}
	p := got[2]

	// Fix (a): severity is max(component severities), not the zero value.
	if p.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL (max of two CRITICAL components)", p.Severity)
	}

	// Fix (c): the band is re-derived from a score, so it is inside the
	// LOW/MEDIUM/HIGH/CRITICAL vocabulary. Both components score 40 → MEDIUM.
	if p.ConfidenceBand != confidence.Band(confidence.PtsRegex) || p.ConfidenceBand != "MEDIUM" {
		t.Errorf("ConfidenceBand = %q, want MEDIUM (Band(40))", p.ConfidenceBand)
	}
	if p.Confidence != confidence.PtsRegex {
		t.Errorf("Confidence = %d, want %d (max of the components' scores)", p.Confidence, confidence.PtsRegex)
	}

	if p.RuleName != "aws_credential_pair" {
		t.Errorf("RuleName = %q, want aws_credential_pair", p.RuleName)
	}
	wantSecret := "aws_access_key_id + aws_secret_access_key found within 1 lines"
	if p.Secret != wantSecret {
		t.Errorf("Secret = %q, want %q (the description, not a matched value)", p.Secret, wantSecret)
	}
	// Context names the two component rule names rather than echoing Secret.
	// The redactor masks Secret inside Context (text.go:70), so with Context ==
	// Secret a --redact'ed pair row printed only "*****" and said nothing about
	// what the pair was. A context that does not contain the secret survives
	// redaction and still identifies the pair.
	wantContext := "correlated pair: aws_access_key_id + aws_secret_access_key"
	if p.Context != wantContext {
		t.Errorf("Context = %q, want %q (component rule names, not the matched line)", p.Context, wantContext)
	}
	if strings.Contains(p.Context, p.Secret) {
		t.Errorf("Context %q contains Secret %q; --redact would mask the whole row", p.Context, p.Secret)
	}
	if p.DetectionMethod != "correlation" {
		t.Errorf("DetectionMethod = %q, want correlation", p.DetectionMethod)
	}
	if p.File != "aws.txt" || p.Line != 1 || p.Column != 20 {
		t.Errorf("position = %s:%d:%d, want aws.txt:1:20 (component A's)", p.File, p.Line, p.Column)
	}
}

// TestCorrelatedSeverityIsMaxOfComponents pins fix (a) on mixed severities. A
// constant would pass the CRITICAL+CRITICAL case above and fail here, which is
// why the value is derived.
func TestCorrelatedSeverityIsMaxOfComponents(t *testing.T) {
	base := awsPair(1, 2)
	base[0].Severity = finding.SeverityHigh
	base[1].Severity = finding.SeverityCritical

	s := NewCorrelationStage(newScanCorrelator(), finding.SeverityInfo)
	got := s.Process(base)

	want := finding.SeverityCritical
	if got[2].Severity != want {
		t.Errorf("Severity = %v, want %v (max of HIGH and CRITICAL)", got[2].Severity, want)
	}
}

// TestCorrelatedBandStaysInVocabulary is the regression guard for fix (c): the
// band may never be a string the scorer cannot produce. It sweeps every score
// the components can carry, so a reintroduced "VERY_HIGH" literal fails here.
func TestCorrelatedBandStaysInVocabulary(t *testing.T) {
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

	base := awsPair(1, 2)
	for _, score := range []int{0, 1, 15, 40, 61, 90, confidence.MaxScore} {
		base[0].Confidence = score
		base[1].Confidence = 0
		s := NewCorrelationStage(newScanCorrelator(), finding.SeverityInfo)
		got := s.Process(base)
		if got[2].ConfidenceBand != confidence.Band(score) {
			t.Errorf("component score %d: band = %q, want %q", score, got[2].ConfidenceBand, confidence.Band(score))
		}
	}
}

// TestCorrelationStageFiltersByMinSeverity pins fix (b): the stage receives
// already-collected findings, so it applies the floor itself. The predecessor of
// this test asserted the opposite — that a pair below the floor was still
// emitted, because Process had no severity input at all.
func TestCorrelationStageFiltersByMinSeverity(t *testing.T) {
	for _, tc := range []struct {
		name string
		min  finding.Severity
		want int
	}{
		{"info floor keeps it", finding.SeverityInfo, 1},
		{"critical floor keeps it", finding.SeverityCritical, 1},
		{"pair below the floor is dropped", finding.SeverityLow, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := awsPair(1, 2)
			if tc.want == 0 {
				// A LOW component drags the pair below the LOW floor.
				base[0].Severity = finding.SeverityInfo
				base[1].Severity = finding.SeverityInfo
			}
			s := NewCorrelationStage(newScanCorrelator(), tc.min)
			if got := len(correlated(s.Process(base))); got != tc.want {
				t.Errorf("got %d pairs, want %d at floor %v", got, tc.want, tc.min)
			}
		})
	}
}

// TestGroupByFileMatchesSingleCall pins that per-file grouping is a cost bound
// and nothing else: it must produce exactly the pairs a single call over the
// whole set produces. matchPair refuses cross-file pairs
// (internal/correlation/helpers.go:18) and DatabaseURLDetector is per-finding,
// so grouping is sound — but it is an optimisation, so it stays pinned.
func TestGroupByFileMatchesSingleCall(t *testing.T) {
	c := newScanCorrelator()
	var corpus []finding.Finding
	corpus = append(corpus, awsPair(1, 2)...)
	corpus = append(corpus, finding.Finding{
		RuleName: "postgres_url", File: "aws.txt", Line: 9,
		Secret: "postgres://app:s3cret@db.example.com:5432/app", Severity: finding.SeverityCritical,
	})
	// Same rule names, different file: must not correlate across files.
	corpus = append(corpus, finding.Finding{
		RuleName: "aws_access_key_id", File: "other.txt", Line: 1, Secret: "AKIAIOSFODNN7EXAMPLE",
	})
	corpus = append(corpus, finding.Finding{
		RuleName: "aws_secret_access_key", File: "third.txt", Line: 3,
		Secret: `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
	})

	var single []correlation.CorrelatedFinding
	single = append(single, c.Correlate(corpus)...)

	var grouped []correlation.CorrelatedFinding
	for _, g := range groupByFile(corpus) {
		grouped = append(grouped, c.Correlate(g)...)
	}

	if len(single) != 2 || len(grouped) != 2 {
		t.Fatalf("single call = %d pairs, grouped = %d pairs, want 2 each", len(single), len(grouped))
	}
	for _, g := range grouped {
		found := false
		for _, s := range single {
			if s.Type == g.Type && s.File == g.File && s.Line == g.Line {
				found = true
			}
		}
		if !found {
			t.Errorf("grouped pair %s at %s:%d has no counterpart in the single call", g.Type, g.File, g.Line)
		}
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

// TestDatabaseURLDetectorIsNotAPair documents what
// internal/correlation/detector_database_url.go actually is: a single-component
// detector that regex-matches finding.Secret, not a matchPair over two rule
// names. So its "components" slice has one element, severity and confidence are
// derived from that one finding, and it needs no second rule to exist.
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

	// And it survives the shared conversion: one component still yields a real
	// severity and an in-band confidence.
	f := correlatedFinding(got[0])
	if f.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL (from its one component)", f.Severity)
	}
	if f.RuleName != "database_url_with_credentials" {
		t.Errorf("RuleName = %q, want database_url_with_credentials", f.RuleName)
	}
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

// TestCorrelationWiringCase1_PairInSpan — an AWS pair inside the detected span
// is reported, with severity and band derived from the components.
func TestCorrelationWiringCase1_PairInSpan(t *testing.T) {
	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": fixtureAWSInSpan}))
	if len(got) != 1 {
		t.Fatalf("got %d correlated findings, want 1", len(got))
	}
	p := got[0]
	if p.RuleName != "aws_credential_pair" {
		t.Errorf("RuleName = %q, want aws_credential_pair", p.RuleName)
	}
	if p.Severity != finding.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL (max of two CRITICAL components)", p.Severity)
	}
	if p.ConfidenceBand != "MEDIUM" {
		t.Errorf("ConfidenceBand = %q, want MEDIUM (Band(40) from the components)", p.ConfidenceBand)
	}
	if want := "aws_access_key_id + aws_secret_access_key found within 1 lines"; p.Secret != want {
		t.Errorf("Secret = %q, want %q", p.Secret, want)
	}
	if p.Line != 1 {
		t.Errorf("Line = %d, want 1 (component A's line)", p.Line)
	}
}

// TestCorrelationWiringCase2_PairBeyondSpan — the same two findings 27 lines
// apart is past AWSDetector's 20-line span, so no pair is reported.
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
	// The components themselves are still found: correlation only ever adds.
	all := scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": body})
	sawA, sawB := false, false
	for _, f := range all {
		switch f.RuleName {
		case "aws_access_key_id":
			sawA = true
		case "aws_secret_access_key":
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Errorf("components found: A=%v B=%v, want both", sawA, sawB)
	}
}

// TestCorrelationWiringCase3_SingleComponent — one component alone reports no
// pair.
func TestCorrelationWiringCase3_SingleComponent(t *testing.T) {
	got := correlated(scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"aws.txt": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"}))
	if len(got) != 0 {
		t.Fatalf("got %d correlated findings, want 0", len(got))
	}
}

// TestCorrelationWiringCase4_MinSeverityStillFilters — a pair is filtered by
// MinSeverity like any other finding.
//
// The fixture sits in a "fixtures" directory because DowngradeFP is the
// easiest way to get a live pair below a floor: it drops both components to
// HIGH against a CRITICAL floor. It is not the only way — database_url_with_
// credentials fires on amqp_connection_url (HIGH) and redis_url_with_password
// (HIGH) as well as on the CRITICAL database-url rules, so a HIGH pair is
// reachable with no downgrade at all. What those HIGH paths lack is a fixture
// here; the filter itself is what this test pins, not the severity it drops.
func TestCorrelationWiringCase4_MinSeverityStillFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		min  finding.Severity
		want int
	}{
		{"critical floor drops the HIGH pair", finding.SeverityCritical, 0},
		{"high floor keeps it", finding.SeverityHigh, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := correlated(scanFixture(t, Config{MinSeverity: tc.min, DowngradeFP: true},
				map[string]string{"fixtures/aws.txt": fixtureAWSInSpan}))
			if len(got) != tc.want {
				t.Fatalf("got %d correlated findings, want %d at floor %v", len(got), tc.want, tc.min)
			}
			if tc.want == 1 && got[0].Severity != finding.SeverityHigh {
				t.Errorf("Severity = %v, want HIGH (DowngradeFP lowered both components)", got[0].Severity)
			}
		})
	}
}

// TestCorrelationWiringCase5_NoCorrelation — the opt-out silences pairs without
// touching the components.
func TestCorrelationWiringCase5_NoCorrelation(t *testing.T) {
	files := map[string]string{"aws.txt": fixtureAWSInSpan}
	if got := correlated(scanFixture(t, Config{
		MinSeverity: finding.SeverityLow, DowngradeFP: true, NoCorrelation: true,
	}, files)); len(got) != 0 {
		t.Fatalf("got %d correlated findings with --no-correlation, want 0", len(got))
	}

	// Same fixture with correlation on still reports both components.
	sawA, sawB := false, false
	for _, f := range scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true}, files) {
		switch f.RuleName {
		case "aws_access_key_id":
			sawA = true
		case "aws_secret_access_key":
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Errorf("components found: A=%v B=%v, want both (the opt-out removes pairs only)", sawA, sawB)
	}
}

// TestCorrelationWiringOnOtherEntryPoints pins that the hook is on each V6
// collection boundary, not just ScanPaths.
func TestCorrelationWiringOnOtherEntryPoints(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	base := Config{Rules: rs, MinSeverity: finding.SeverityLow, DowngradeFP: true}

	got := ScanContent(fixtureAWSInSpan, "stdin", base)
	if len(correlated(got)) != 1 {
		t.Errorf("ScanContent: got %d correlated findings, want 1", len(correlated(got)))
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "aws.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(fixtureAWSInSpan); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err = ScanReader(reader, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(correlated(got)) != 1 {
		t.Errorf("ScanReader: got %d correlated findings, want 1", len(correlated(got)))
	}
}

// TestCorrelationWiringDoesNotDuplicateThroughScanFiles guards the hook
// placement: ScanPaths reaches findings through ScanFile, which must not
// correlate a second time on the way up.
func TestCorrelationWiringDoesNotDuplicateThroughScanFiles(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "aws.txt")
	if err := os.WriteFile(p, []byte(fixtureAWSInSpan), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow, DowngradeFP: true}

	viaPaths, err := ScanPaths([]string{p}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	viaFile, err := ScanFile(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(correlated(viaPaths)); n != 1 {
		t.Errorf("ScanPaths reported %d pairs, want 1 (a second hook in ScanFile would double it)", n)
	}
	if n := len(correlated(viaFile)); n != 0 {
		t.Errorf("ScanFile reported %d pairs, want 0 (ScanPaths is the boundary)", n)
	}
}

// TestCorrelationWiringMultiplePairsInOneFile checks a file holding one pair of
// each kind that can fire under the current ruleset: three credential pairs plus
// the single-component database-URL detector.
func TestCorrelationWiringMultiplePairsInOneFile(t *testing.T) {
	body := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n" +
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc\n" +
		"pk_live_TYooMQauvdEDq54NiTphI7jx\n" +
		"twilio_account_sid = AC1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\n" +
		"twilio_auth_token = \"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\"\n" +
		"db = \"postgres://app:s3cret@db-host.internal:5432/app\"\n"

	all := scanFixture(t, Config{MinSeverity: finding.SeverityLow, DowngradeFP: true},
		map[string]string{"all.txt": body})

	// Guard the fixture itself: if a component rule stops matching, the pair
	// assertions below would fail for a reason that has nothing to do with
	// correlation.
	for _, want := range []string{"aws_access_key_id", "aws_secret_access_key", "stripe_secret_key",
		"stripe_publishable_key", "twilio_account_sid", "twilio_auth_token", "postgres_url"} {
		found := false
		for _, f := range all {
			if f.RuleName == want {
				found = true
			}
		}
		if !found {
			t.Errorf("component %s not found — the fixture no longer trips it", want)
		}
	}

	seen := map[string]bool{}
	for _, p := range correlated(all) {
		seen[p.RuleName] = true
	}
	for _, name := range []string{
		"aws_credential_pair",
		"stripe_credential_pair",
		"twilio_credential_pair",
		"database_url_with_credentials",
	} {
		if !seen[name] {
			t.Errorf("%s not reported; pairs seen: %v", name, seen)
		}
	}
}

func BenchmarkCorrelateFindings(b *testing.B) {
	rs, err := rules.LoadDefault()
	if err != nil {
		b.Fatal(err)
	}
	cfg := Config{Rules: rs, MinSeverity: finding.SeverityLow}

	// 2,000 pair components (1,000 pairs) plus 8,000 unrelated findings,
	// spread across 500 files.
	var findings []finding.Finding
	for i := 0; i < 1000; i++ {
		file := fmt.Sprintf("src/file%03d.go", i%500)
		findings = append(findings, finding.Finding{
			RuleName: "aws_access_key_id", File: file, Line: 2, Column: 20, Secret: "AKIAIOSFODNN7EXAMPLE",
			Severity: finding.SeverityCritical, Confidence: confidence.PtsRegex,
		})
		findings = append(findings, finding.Finding{
			RuleName: "aws_secret_access_key", File: file, Line: 3,
			Secret:   `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			Severity: finding.SeverityCritical, Confidence: confidence.PtsRegex,
		})
	}
	for i := 0; i < 8000; i++ {
		findings = append(findings, finding.Finding{
			RuleName: "high_entropy_token", File: fmt.Sprintf("src/file%03d.go", i%500), Line: 10 + i,
			Secret: fmt.Sprintf("entropy-token-value-%d", i), Severity: finding.SeverityMedium,
			Confidence: confidence.PtsEntropy + confidence.PtsContext,
		})
	}
	n := len(findings)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Three-index slice so the append inside correlateFindings cannot grow
		// the benchmark's own input: without it each iteration re-correlates
		// the previous iteration's pairs too.
		_ = correlateFindings(cfg, findings[:n:n])
	}
}

// TestCollapsePairsMergesSameCorrelation pins the dedup that keeps one
// .env line carrying a credential-bearing URL from producing three rows.
//
// database_url_with_credentials fires once per matching finding, not once per
// URL: REDIS_URL=redis://default:s3cret@host:6379 matches dotenv_file_secret,
// redis_url and redis_url_with_password, all three of which report the same
// Secret. Without the collapse the scan prints three rows with contradictory
// severities for one URL, on an ordinary .env line, and --severity ends up
// doing triage the emission should have done.
func TestCollapsePairsMergesSameCorrelation(t *testing.T) {
	desc := "database_url_with_credential_probe"
	mk := func(sev finding.Severity, conf int) finding.Finding {
		return finding.Finding{
			RuleName: "database_url_with_credentials", File: "a.env", Line: 1,
			Secret: desc, Context: "correlated finding on redis_url",
			DetectionMethod: "correlation", Severity: sev, Confidence: conf,
		}
	}

	// The order deliberately puts the LOW-severity row first: finding.Deduplicate
	// would keep it, silently lowering the pair below its own worst component.
	in := []finding.Finding{mk(finding.SeverityHigh, 40), mk(finding.SeverityCritical, 40), mk(finding.SeverityHigh, 40)}
	got := collapsePairs(in)
	if len(got) != 1 {
		t.Fatalf("collapsePairs returned %d rows, want 1: %+v", len(got), got)
	}
	if got[0].Severity != finding.SeverityCritical {
		t.Errorf("collapsed severity = %v, want CRITICAL (max, not first)", got[0].Severity)
	}

	// Distinct correlations must not be merged: different rule name, different
	// line, and different context each survive.
	other := got[0]
	other.RuleName = "aws_credential_pair"
	other.Context = "correlated pair: aws_access_key_id + aws_secret_access_key"
	if n := len(collapsePairs(append([]finding.Finding{got[0]}, other))); n != 2 {
		t.Errorf("distinct pairs collapsed to %d, want 2", n)
	}
}
