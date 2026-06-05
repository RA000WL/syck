package recon

import "testing"

func TestMetricsDetectorPositive(t *testing.T) {
	d := MetricsDetector{}
	got := d.Detect([]string{"https://example.com/metrics"})
	if len(got) != 1 || got[0].Category != "metrics" {
		t.Fatal("expected metrics finding")
	}
}

func TestMetricsDetectorNegative(t *testing.T) {
	d := MetricsDetector{}
	got := d.Detect([]string{"https://example.com/index.html"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
