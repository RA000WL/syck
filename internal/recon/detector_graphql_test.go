package recon

import "testing"

func TestGraphQLDetectorPositive(t *testing.T) {
	d := GraphQLDetector{}
	got := d.Detect([]string{"https://example.com/graphql"})
	if len(got) != 1 {
		t.Fatal("expected 1 finding")
	}
	if got[0].Category != "graphql" {
		t.Errorf("Category = %q", got[0].Category)
	}
}

func TestGraphQLDetectorNegative(t *testing.T) {
	d := GraphQLDetector{}
	got := d.Detect([]string{"https://example.com/api"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
