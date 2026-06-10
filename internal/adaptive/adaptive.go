// Package adaptive implements the adaptive confidence learning engine.
// It provides file pattern extraction, tier classification, and weighted
// statistics for the syck verdict feedback system.
package adaptive

import (
	"math"
	"path/filepath"
	"strings"
	"time"
)

// Tier represents the learning maturity of a (rule, file_pattern) combo.
type Tier int

const (
	TierExperimental Tier = 0
	TierLearning     Tier = 1
	TierMature       Tier = 2
	TierTrusted      Tier = 3
)

func (t Tier) Label() string {
	switch t {
	case TierExperimental:
		return "Experimental"
	case TierLearning:
		return "Learning"
	case TierMature:
		return "Mature"
	case TierTrusted:
		return "Trusted"
	default:
		return "Unknown"
	}
}

func ClassifyTier(sampleCount int) Tier {
	switch {
	case sampleCount >= 200:
		return TierTrusted
	case sampleCount >= 50:
		return TierMature
	case sampleCount >= 10:
		return TierLearning
	default:
		return TierExperimental
	}
}

// Verdict represents a single user verdict on a finding.
type Verdict struct {
	Fingerprint string
	Verdict     string // "tp" or "fp"
	CreatedAt   time.Time
}

// LearnedWeight stores the precomputed learning data for a (rule, file_pattern) combo.
type LearnedWeight struct {
	RuleName    string
	FilePattern string
	TPWeighted  float64
	FPWeighted  float64
	SampleCount int
	Tier        Tier
	Modifier    float64
}

// ExtractFilePattern reduces a file path to a canonical pattern for learning.
func ExtractFilePattern(filePath string) string {
	lower := strings.ToLower(filePath)
	parts := strings.Split(lower, "/")

	for i := 0; i < len(parts)-1; i++ {
		dir := parts[i]
		if dir == "test" || dir == "tests" || dir == "__tests__" {
			return "*/test/*"
		}
		if dir == "mock" || dir == "mocks" || dir == "__mocks__" {
			return "*/mock/*"
		}
		if dir == "vendor" {
			return "*/vendor/*"
		}
		if dir == "node_modules" {
			return "*/node_modules/*"
		}
		if dir == "example" || dir == "examples" || dir == "fixtures" {
			return "*/example/*"
		}
	}

	ext := filepath.Ext(filePath)
	if ext != "" {
		return "*" + ext
	}
	return "*"
}

// DecayHalfLife is the half-life for exponential decay of verdict weights.
const DecayHalfLife = 90.0 // days

// ComputeWeightedStats returns decay-weighted FP and TP counts and total sample count.
func ComputeWeightedStats(verdicts []Verdict) (weightedFP, weightedTP float64, sampleCount int) {
	now := time.Now()
	for _, v := range verdicts {
		ageDays := now.Sub(v.CreatedAt).Hours() / 24.0
		w := math.Exp(-ageDays / DecayHalfLife)
		if v.Verdict == "fp" {
			weightedFP += w
		} else {
			weightedTP += w
		}
		sampleCount++
	}
	return
}

// High-certainty rules that should never be heavily penalized.
var highCertaintyRules = map[string]bool{
	"aws_access_key":     true,
	"github_pat":         true,
	"stripe_live_key":    true,
	"private_key":        true,
	"aws_secret_key":     true,
	"github_oauth_token": true,
	"stripe_restricted":  true,
}

func isHighCertainty(ruleName string) bool {
	return highCertaintyRules[ruleName]
}

func clamp(low, high, val float64) float64 {
	if val < low {
		return low
	}
	if val > high {
		return high
	}
	return val
}

// ComputeModifier computes the adaptive confidence modifier for a rule
// given its verdict history. Uses Bayesian smoothing, minimum evidence
// ramp-up, per-rule caps, and clamping.
func ComputeModifier(ruleName string, verdicts []Verdict) float64 {
	if len(verdicts) == 0 {
		return 0
	}

	weightedFP, weightedTP, sampleCount := ComputeWeightedStats(verdicts)

	// Step 1: Bayesian smoothing (prior: 5 TP + 5 FP)
	smoothedFPRatio := (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)

	// Step 2: Base modifier
	modifier := (1 - 2*smoothedFPRatio) * 40

	// Step 3: Minimum evidence ramp-up
	if sampleCount < 20 {
		modifier *= float64(sampleCount) / 20.0
	}

	// Step 4: Per-rule cap
	if isHighCertainty(ruleName) && modifier < -10 {
		modifier = -10
	}

	// Step 5: Clamp
	return clamp(-40, 40, modifier)
}

// LearnedWeightStore is an in-memory store of learned weights.
type LearnedWeightStore struct {
	weights map[string]*LearnedWeight // key: "ruleName|filePattern"
}

func NewLearnedWeightStore() *LearnedWeightStore {
	return &LearnedWeightStore{weights: make(map[string]*LearnedWeight)}
}

func (s *LearnedWeightStore) Set(ruleName, filePattern string, tpWeighted, fpWeighted float64, sampleCount int) {
	key := ruleName + "|" + filePattern
	modifier := ComputeModifierFromStats(ruleName, fpWeighted, tpWeighted, sampleCount)
	s.weights[key] = &LearnedWeight{
		RuleName:    ruleName,
		FilePattern: filePattern,
		TPWeighted:  tpWeighted,
		FPWeighted:  fpWeighted,
		SampleCount: sampleCount,
		Tier:        ClassifyTier(sampleCount),
		Modifier:    modifier,
	}
}

func (s *LearnedWeightStore) Get(ruleName, filePattern string) *LearnedWeight {
	key := ruleName + "|" + filePattern
	return s.weights[key]
}

// ComputeModifierFromStats computes a modifier from pre-aggregated stats.
func ComputeModifierFromStats(ruleName string, weightedFP, weightedTP float64, sampleCount int) float64 {
	if sampleCount == 0 {
		return 0
	}
	smoothedFPRatio := (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)
	modifier := (1 - 2*smoothedFPRatio) * 40
	if sampleCount < 20 {
		modifier *= float64(sampleCount) / 20.0
	}
	if isHighCertainty(ruleName) && modifier < -10 {
		modifier = -10
	}
	return clamp(-40, 40, modifier)
}
