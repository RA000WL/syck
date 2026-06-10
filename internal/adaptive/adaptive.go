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
