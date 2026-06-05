package recon

import "testing"

func TestAuthDetectorPositive(t *testing.T) {
	d := AuthDetector{}
	got := d.Detect([]string{"https://example.com/oauth/token"})
	if len(got) == 0 || got[0].Category != "auth" {
		t.Fatal("expected auth finding")
	}
}

func TestAuthDetectorNegative(t *testing.T) {
	d := AuthDetector{}
	got := d.Detect([]string{"https://example.com/api"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
