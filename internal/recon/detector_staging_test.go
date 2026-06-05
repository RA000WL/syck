package recon

import "testing"

func TestStagingDetectorPositive(t *testing.T) {
	d := StagingDetector{}
	got := d.Detect([]string{"https://staging.example.com/api"})
	if len(got) == 0 || got[0].Category != "staging" {
		t.Fatal("expected staging finding")
	}
}

func TestStagingDetectorNegative(t *testing.T) {
	d := StagingDetector{}
	got := d.Detect([]string{"https://example.com/api"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
