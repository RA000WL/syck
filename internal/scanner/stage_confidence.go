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
			RegexMatch:        isRegexMatch(in[i].DetectionMethod, in[i].RuleName),
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

// isRegexMatch derives the regex signal from DetectionMethod. The pipeline
// Rule/Decoder stages predate DetectionMethod and leave it empty, so an
// empty method falls back to the rule-name heuristic (only "entropy_token"
// is a known non-regex producer there); every other empty-method finding is
// a regex hit.
func isRegexMatch(method, ruleName string) bool {
	switch method {
	case "regex", "decoded_regex", "regex+expiry":
		return true
	case "":
		return ruleName != "entropy_token"
	default:
		return false
	}
}
