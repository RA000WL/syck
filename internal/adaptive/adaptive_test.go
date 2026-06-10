package adaptive

import (
	"testing"
	"time"
)

func TestExtractFilePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"src/components/App.js", "*.js"},
		{"test/config.test.js", "*/test/*"},
		{"tests/helpers.js", "*/test/*"},
		{"__tests__/unit.js", "*/test/*"},
		{"mocks/api.js", "*/mock/*"},
		{"__mocks__/file.js", "*/mock/*"},
		{"vendor/lib.go", "*/vendor/*"},
		{"node_modules/pkg/index.js", "*/node_modules/*"},
		{"example/config.env", "*/example/*"},
		{"examples/setup.js", "*/example/*"},
		{"fixtures/data.json", "*/example/*"},
		{"Makefile", "*"},
		{".env", "*.env"},
		{"config.yaml", "*.yaml"},
	}
	for _, tt := range tests {
		got := ExtractFilePattern(tt.input)
		if got != tt.want {
			t.Errorf("ExtractFilePattern(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClassifyTier(t *testing.T) {
	tests := []struct {
		sampleCount int
		want        Tier
	}{
		{0, TierExperimental},
		{5, TierExperimental},
		{9, TierExperimental},
		{10, TierLearning},
		{25, TierLearning},
		{49, TierLearning},
		{50, TierMature},
		{100, TierMature},
		{199, TierMature},
		{200, TierTrusted},
		{500, TierTrusted},
	}
	for _, tt := range tests {
		got := ClassifyTier(tt.sampleCount)
		if got != tt.want {
			t.Errorf("ClassifyTier(%d) = %v, want %v", tt.sampleCount, got, tt.want)
		}
	}
}

func TestTierLabel(t *testing.T) {
	if TierExperimental.Label() != "Experimental" {
		t.Errorf("got %q", TierExperimental.Label())
	}
	if TierLearning.Label() != "Learning" {
		t.Errorf("got %q", TierLearning.Label())
	}
	if TierMature.Label() != "Mature" {
		t.Errorf("got %q", TierMature.Label())
	}
	if TierTrusted.Label() != "Trusted" {
		t.Errorf("got %q", TierTrusted.Label())
	}
}

func TestComputeModifier_BayesianSmoothing(t *testing.T) {
	verdicts := []Verdict{
		{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)},
	}
	mod := ComputeModifier("generic_api_key", verdicts)
	if mod > 1 || mod < -1 {
		t.Errorf("1 FP, 0 TP: modifier should be near 0 due to smoothing + ramp, got %f", mod)
	}
}

func TestComputeModifier_AllFP_Heavy(t *testing.T) {
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("generic_api_key", verdicts)
	if mod > -30 {
		t.Errorf("100 FP, 0 TP: modifier should be heavily negative, got %f", mod)
	}
}

func TestComputeModifier_AllTP_Boost(t *testing.T) {
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "tp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("aws_access_key", verdicts)
	if mod < 30 {
		t.Errorf("100 TP, 0 FP: modifier should be heavily positive, got %f", mod)
	}
}

func TestComputeModifier_MinimumEvidenceRampUp(t *testing.T) {
	verdicts5 := make([]Verdict, 5)
	for i := range verdicts5 {
		verdicts5[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod5 := ComputeModifier("generic_api_key", verdicts5)

	verdicts20 := make([]Verdict, 20)
	for i := range verdicts20 {
		verdicts20[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod20 := ComputeModifier("generic_api_key", verdicts20)

	if mod5 < mod20 {
		t.Errorf("ramp-up failed: mod5=%f should be less negative than mod20=%f", mod5, mod20)
	}
}

func TestComputeModifier_HighCertaintyCap(t *testing.T) {
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("aws_access_key", verdicts)
	if mod < -10 {
		t.Errorf("high-certainty rule capped at -10, got %f", mod)
	}
}

func TestComputeModifier_Empty(t *testing.T) {
	mod := ComputeModifier("any_rule", nil)
	if mod != 0 {
		t.Errorf("empty verdicts should return 0, got %f", mod)
	}
}

func TestComputeModifier_Clamp(t *testing.T) {
	verdicts := make([]Verdict, 500)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "tp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("generic_api_key", verdicts)
	if mod > 40 {
		t.Errorf("modifier should clamp at 40, got %f", mod)
	}
	if mod < -40 {
		t.Errorf("modifier should clamp at -40, got %f", mod)
	}
}

func TestHighCertaintyRules(t *testing.T) {
	rules := []string{"aws_access_key", "github_pat", "stripe_live_key", "private_key"}
	for _, r := range rules {
		if !isHighCertainty(r) {
			t.Errorf("expected %s to be high-certainty", r)
		}
	}
	if isHighCertainty("generic_api_key") {
		t.Error("generic_api_key should not be high-certainty")
	}
}

func TestLearnedWeightStore_Lookup(t *testing.T) {
	store := NewLearnedWeightStore()
	store.Set("generic_api_key", "*.test.js", 10, 80, 90)
	w := store.Get("generic_api_key", "*.test.js")
	if w == nil {
		t.Fatal("expected weight, got nil")
	}
	if w.Tier != TierMature {
		t.Errorf("expected Mature tier, got %v", w.Tier)
	}
}

func TestLearnedWeightStore_Default(t *testing.T) {
	store := NewLearnedWeightStore()
	w := store.Get("unknown_rule", "*.js")
	if w != nil {
		t.Error("expected nil for unknown rule")
	}
}

func TestLearnedWeightStore_ModifierComputation(t *testing.T) {
	store := NewLearnedWeightStore()
	// All FP → should have negative modifier
	store.Set("generic_api_key", "*.js", 0, 50, 50)
	w := store.Get("generic_api_key", "*.js")
	if w.Modifier >= 0 {
		t.Errorf("all FPs should have negative modifier, got %f", w.Modifier)
	}
}
