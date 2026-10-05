package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/rules"
)

// Crafted secrets whose Shannon entropy straddles the thresholds under test.
const (
	lowEntropySecret  = "ZqZqWwWwWwWwXxXx"   // ~2.5 bits: above the 2.0 floor, below 3.0
	highEntropySecret = "kR7mZp2WqL9xVb3HjT" // ~4.17 bits: above 3.0
	deepLowSecret     = "AbAbAbAbAbAbCdCdCd" // ~1.92 bits: below the 2.0 floor
)

// requireEntropyBands guards the test fixtures: the assertions below are only
// meaningful while the crafted secrets keep straddling 2.0 and 3.0.
func requireEntropyBands(t *testing.T) {
	t.Helper()
	if e := entropy.Shannon(lowEntropySecret); e < 2.0 || e >= 3.0 {
		t.Fatalf("lowEntropySecret entropy = %v, want [2.0, 3.0)", e)
	}
	if e := entropy.Shannon(highEntropySecret); e <= 3.5 {
		t.Fatalf("highEntropySecret entropy = %v, want > 3.5", e)
	}
	if e := entropy.Shannon(deepLowSecret); e >= 2.0 {
		t.Fatalf("deepLowSecret entropy = %v, want < 2.0", e)
	}
}

// entropyGatedRuleSet builds one compiled rule matching the crafted secrets.
func entropyGatedRuleSet(t *testing.T, threshold float64) *rules.RuleSet {
	t.Helper()
	rs := &rules.RuleSet{
		Rules: []rules.Rule{
			{
				Name:             "entropy_gated",
				Severity:         "HIGH",
				Pattern:          `[A-Za-z0-9]{16,}`,
				EntropyThreshold: threshold,
			},
		},
	}
	if err := rs.CompileAll(); err != nil {
		t.Fatalf("CompileAll: %v", err)
	}
	return rs
}

func TestPerRuleEntropyThresholdEnforced(t *testing.T) {
	requireEntropyBands(t)
	rs := entropyGatedRuleSet(t, 3.0)
	cfg := Config{Rules: rs}

	t.Run("below_threshold_suppressed", func(t *testing.T) {
		line := "password = " + lowEntropySecret
		got := scanLineForRegexRulesChunk(line, 1, "t.txt", cfg, "", nil, rs.Rules, 0)
		if len(got) != 0 {
			t.Fatalf("entropy %.3f under 3.0 threshold: expected 0 findings, got %d: %+v",
				entropy.Shannon(lowEntropySecret), len(got), got)
		}
	})

	t.Run("above_threshold_reported", func(t *testing.T) {
		line := "password = " + highEntropySecret
		got := scanLineForRegexRulesChunk(line, 1, "t.txt", cfg, "", nil, rs.Rules, 0)
		if len(got) != 1 {
			t.Fatalf("entropy %.3f over 3.0 threshold: expected 1 finding, got %d: %+v",
				entropy.Shannon(highEntropySecret), len(got), got)
		}
	})
}

func TestZeroThresholdKeepsFloor(t *testing.T) {
	requireEntropyBands(t)
	rs := entropyGatedRuleSet(t, 0)
	cfg := Config{Rules: rs}

	t.Run("above_floor_reported", func(t *testing.T) {
		// ~2.5-entropy match: threshold unset, so the 2.0 floor still fires it.
		line := "password = " + lowEntropySecret
		got := scanLineForRegexRulesChunk(line, 1, "t.txt", cfg, "", nil, rs.Rules, 0)
		if len(got) != 1 {
			t.Fatalf("entropy %.3f over 2.0 floor: expected 1 finding, got %d: %+v",
				entropy.Shannon(lowEntropySecret), len(got), got)
		}
	})

	t.Run("below_floor_suppressed", func(t *testing.T) {
		line := "password = " + deepLowSecret
		got := scanLineForRegexRulesChunk(line, 1, "t.txt", cfg, "", nil, rs.Rules, 0)
		if len(got) != 0 {
			t.Fatalf("entropy %.3f under 2.0 floor: expected 0 findings, got %d: %+v",
				entropy.Shannon(deepLowSecret), len(got), got)
		}
	})
}

// TestPerRuleEntropyThresholdStreaming guards the streaming regex loop
// (scanFileStreaming), which has its own copy of the entropy floor check.
func TestPerRuleEntropyThresholdStreaming(t *testing.T) {
	requireEntropyBands(t)
	rs := entropyGatedRuleSet(t, 3.0)
	cfg := Config{Rules: rs, MaxFileSize: 100 << 20}

	writePayload := func(t *testing.T, secret string) string {
		t.Helper()
		var b strings.Builder
		for b.Len() <= 1024*1024 {
			b.WriteString("filler line here\n")
		}
		b.WriteString(secret)
		b.WriteString("\n")
		p := filepath.Join(t.TempDir(), "big.txt")
		if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	countRule := func(t *testing.T, path string) int {
		t.Helper()
		findings, err := ScanFile(path, cfg)
		if err != nil {
			t.Fatalf("ScanFile: %v", err)
		}
		n := 0
		for _, f := range findings {
			if f.RuleName == "entropy_gated" {
				n++
			}
		}
		return n
	}

	t.Run("below_threshold_suppressed", func(t *testing.T) {
		path := writePayload(t, lowEntropySecret)
		if n := countRule(t, path); n != 0 {
			t.Fatalf("entropy %.3f under 3.0 threshold: expected 0 findings, got %d",
				entropy.Shannon(lowEntropySecret), n)
		}
	})

	t.Run("above_threshold_reported", func(t *testing.T) {
		path := writePayload(t, highEntropySecret)
		if n := countRule(t, path); n != 1 {
			t.Fatalf("entropy %.3f over 3.0 threshold: expected 1 finding, got %d",
				entropy.Shannon(highEntropySecret), n)
		}
	})
}
