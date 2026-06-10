package adaptive

import "testing"

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
