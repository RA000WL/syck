// internal/confidence/confidence_test.go
package confidence

import "testing"

func TestScorerAllSignals(t *testing.T) {
	s := NewScorer()
	got := s.Score(Signals{RegexMatch: true, Entropy: 5.0, HasContextKeyword: true, Verified: true, InCredentialPair: true})
	if got != 155 {
		t.Errorf("Score() = %d, want 155", got)
	}
	if Band(got) != "CRITICAL" {
		t.Errorf("Band(155) = %q, want CRITICAL", Band(got))
	}
}

func TestScorerNoSignals(t *testing.T) {
	s := NewScorer()
	got := s.Score(Signals{})
	if got != 0 {
		t.Errorf("Score() = %d, want 0", got)
	}
	if Band(got) != "LOW" {
		t.Errorf("Band(0) = %q, want LOW", Band(got))
	}
}

func TestBandBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{30, "LOW"}, {31, "MEDIUM"},
		{60, "MEDIUM"}, {61, "HIGH"},
		{90, "HIGH"}, {91, "CRITICAL"},
	}
	for _, c := range cases {
		if got := Band(c.score); got != c.want {
			t.Errorf("Band(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestEntropySignal(t *testing.T) {
	s := NewScorer()
	if got := s.Score(Signals{Entropy: 4.5}); got != 20 {
		t.Errorf("Score(entropy=4.5) = %d, want 20", got)
	}
	if got := s.Score(Signals{Entropy: 4.4}); got != 0 {
		t.Errorf("Score(entropy=4.4) = %d, want 0", got)
	}
}
