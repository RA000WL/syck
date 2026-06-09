package scanner

import (
	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/finding"
)

type ConfidenceStage struct {
	scorer *confidence.Scorer
}

func NewConfidenceStage() *ConfidenceStage { return &ConfidenceStage{scorer: confidence.NewScorer()} }

func (s *ConfidenceStage) Process(in []finding.Finding) []finding.Finding {
	for i := range in {
		sig := confidence.Signals{
			RegexMatch:        in[i].RuleName != "entropy_token",
			Entropy:           in[i].Entropy,
			HasContextKeyword: false,
			Verified:          in[i].VerificationStatus == "VERIFIED",
			InCredentialPair:  false,
		}
		if sig.Entropy == 0 && in[i].Secret != "" {
			sig.Entropy = entropy.Shannon(in[i].Secret)
		}
		score := s.scorer.Score(sig)
		in[i].ConfidenceBand = confidence.Band(score)
	}
	return in
}
