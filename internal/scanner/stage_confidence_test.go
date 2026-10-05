package scanner

import (
	"testing"

	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/finding"
)

// When a finding already carries a score, the stage must derive the band from
// that number. Re-scoring here uses different inputs than the scan sites used
// (no context keyword, no credential pair), so band and number could disagree.
func TestConfidenceStageDerivesBandFromExistingScore(t *testing.T) {
	s := NewConfidenceStage()
	got := s.Process([]finding.Finding{{
		RuleName:        "dotenv_file_secret",
		Secret:          "AKIAIOSFODNN7EXAMPLE",
		Confidence:      55,
		ConfidenceBand:  "WRONG",
		DetectionMethod: "entropy+context",
		Entropy:         4.0,
	}})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Confidence != 55 {
		t.Errorf("Confidence = %d, want 55 (stage must not rescore)", got[0].Confidence)
	}
	if want := confidence.Band(55); got[0].ConfidenceBand != want {
		t.Errorf("ConfidenceBand = %q, want %q (Band(55))", got[0].ConfidenceBand, want)
	}
}

func TestConfidenceStageScoresWhenConfidenceIsZero(t *testing.T) {
	s := NewConfidenceStage()
	got := s.Process([]finding.Finding{{
		RuleName:        "dotenv_file_secret",
		Secret:          "AKIAIOSFODNN7EXAMPLE",
		DetectionMethod: "entropy+context",
		Entropy:         5.0,
	}})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].ConfidenceBand == "" {
		t.Error("ConfidenceBand empty; scoring fallback did not run for Confidence == 0")
	}
}
