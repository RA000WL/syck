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
	PtsRegex    = 40
	PtsEntropy  = 20
	PtsContext  = 15
	PtsVerified = 50
	PtsCredPair = 30
	// EntropyFloor is the minimum Shannon entropy for the entropy signal.
	EntropyFloor = 4.5
	// MaxScore caps the unified confidence scale.
	MaxScore = 120
)

func (s *Scorer) Score(sig Signals) int {
	score := 0
	if sig.RegexMatch {
		score += PtsRegex
	}
	if sig.Entropy >= EntropyFloor {
		score += PtsEntropy
	}
	if sig.HasContextKeyword {
		score += PtsContext
	}
	if sig.Verified {
		score += PtsVerified
	}
	if sig.InCredentialPair {
		score += PtsCredPair
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
	if adjusted > MaxScore {
		adjusted = MaxScore
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
	case score <= MaxScore:
		return "CRITICAL"
	default:
		return "VERY_HIGH"
	}
}
