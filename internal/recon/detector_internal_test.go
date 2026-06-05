package recon

import "testing"

func TestInternalDetectorPositive(t *testing.T) {
	d := InternalDetector{}
	got := d.Detect([]string{"https://internal.example.com/secret"})
	if len(got) == 0 || got[0].Category != "internal" {
		t.Fatal("expected internal finding")
	}
}

func TestInternalDetectorNegative(t *testing.T) {
	d := InternalDetector{}
	got := d.Detect([]string{"https://example.com/public"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
