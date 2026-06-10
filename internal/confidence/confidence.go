package confidence

type Signals struct {
	RegexMatch        bool
	Entropy           float64
	HasContextKeyword bool
	Verified          bool
	InCredentialPair  bool
}

type Scorer struct{}

func NewScorer() *Scorer { return &Scorer{} }

const (
	ptsRegex     = 40
	ptsEntropy   = 20
	ptsContext   = 15
	ptsVerified  = 50
	ptsCredPair  = 30
	entropyFloor = 4.5
)

func (s *Scorer) Score(sig Signals) int {
	score := 0
	if sig.RegexMatch {
		score += ptsRegex
	}
	if sig.Entropy >= entropyFloor {
		score += ptsEntropy
	}
	if sig.HasContextKeyword {
		score += ptsContext
	}
	if sig.Verified {
		score += ptsVerified
	}
	if sig.InCredentialPair {
		score += ptsCredPair
	}
	return score
}

// ScoreWithAdaptive computes confidence and applies an adaptive modifier.
func (s *Scorer) ScoreWithAdaptive(sig Signals, adaptiveMod int) int {
	base := s.Score(sig)
	adjusted := base + adaptiveMod
	if adjusted < 0 {
		adjusted = 0
	}
	if adjusted > 120 {
		adjusted = 120
	}
	return adjusted
}

func Band(score int) string {
	switch {
	case score <= 30:
		return "LOW"
	case score <= 60:
		return "MEDIUM"
	case score <= 90:
		return "HIGH"
	case score <= 120:
		return "CRITICAL"
	default:
		return "VERY_HIGH"
	}
}
