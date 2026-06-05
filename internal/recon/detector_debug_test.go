package recon

import "testing"

func TestDebugDetectorPositive(t *testing.T) {
	d := DebugDetector{}
	got := d.Detect([]string{"https://example.com/debug"})
	if len(got) != 1 || got[0].Category != "debug" {
		t.Fatal("expected debug finding")
	}
}

func TestDebugDetectorNegative(t *testing.T) {
	d := DebugDetector{}
	got := d.Detect([]string{"https://example.com/api"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
