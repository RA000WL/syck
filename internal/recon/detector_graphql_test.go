package recon

import "testing"

func TestGraphQLDetectorPositive(t *testing.T) {
	d := NewGraphQLDetector(nil)
	got := d.Detect([]string{"https://example.com/graphql"})
	if len(got) != 1 {
		t.Fatal("expected 1 finding")
	}
	if got[0].Category != "graphql" {
		t.Errorf("Category = %q", got[0].Category)
	}
}

func TestGraphQLDetectorNegative(t *testing.T) {
	d := NewGraphQLDetector(nil)
	got := d.Detect([]string{"https://example.com/api"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestIsSecretFieldName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"password", true},
		{"apiKey", true},
		{"secret_key", true},
		{"id", false},
		{"name", false},
		{"createdAt", false},
	}
	for _, tt := range tests {
		if got := isSecretFieldName(tt.name); got != tt.want {
			t.Errorf("isSecretFieldName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestIsSensitiveFieldName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"users", true},
		{"secrets", true},
		{"id", false},
		{"name", false},
	}
	for _, tt := range tests {
		if got := isSensitiveFieldName(tt.name); got != tt.want {
			t.Errorf("isSensitiveFieldName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
