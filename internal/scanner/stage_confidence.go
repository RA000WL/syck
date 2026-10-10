package scanner

import (
	"strings"

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
		// A finding that already carries a score was scored by a scan site
		// with more inputs than this stage can see (context keyword,
		// credential pair, decoder provenance). Re-deriving the band from
		// this stage's own signal set would let the band and the number
		// disagree, and the band is a triage field keyed off RuleName — so
		// only rescore when there is no score at all.
		if in[i].Confidence != 0 {
			in[i].ConfidenceBand = confidence.Band(in[i].Confidence)
			continue
		}
		sig := confidence.Signals{
			RegexMatch:        isRegexMatch(in[i].DetectionMethod, in[i].RuleName),
			Entropy:           in[i].Entropy,
			HasContextKeyword: false,
			Verified:          in[i].VerificationStatus == "VERIFIED",
			InCredentialPair:  isCredentialPair(in[i].RuleName),
		}
		if sig.Entropy == 0 && in[i].Secret != "" {
			sig.Entropy = entropy.Shannon(in[i].Secret)
		}
		score := s.scorer.Score(sig)
		in[i].ConfidenceBand = confidence.Band(score)
	}
	return in
}

// isCredentialPair reports whether ruleName names a correlation of two or more
// findings into one credential.
//
// The credential-pair detectors all name their type with a _credential_pair
// suffix; database_url_with_credentials does not, because it is not a pair —
// DatabaseURLDetector matches a single finding's own Secret against a
// database-URL pattern and reports that finding, so its Components list has
// length 1. Giving it the pair bonus would inflate a one-component finding.
//
// The suffix is a derived predicate, not a hardcoded list, so a new
// matchPair detector is picked up by following the existing naming convention.
// TestIsCredentialPairPinsTheDetectorTypes enumerates the types
// newScanCorrelator can emit for a pair and asserts each one clears it, which
// is what fails if someone names a detector type differently.
//
// Note that on the CLI this signal is currently inert in practice: correlated
// findings carry a Confidence set by correlateFindings, and Process rescores
// only when Confidence is 0 (above), so it skips them. Wiring this makes the
// dormant Pipeline correct rather than changing live output.
func isCredentialPair(ruleName string) bool {
	return strings.HasSuffix(ruleName, "_credential_pair")
}

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
