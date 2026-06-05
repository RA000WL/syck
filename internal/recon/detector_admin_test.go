package recon

import "testing"

func TestAdminDetectorPositive(t *testing.T) {
	d := AdminDetector{}
	got := d.Detect([]string{"https://example.com/admin/users"})
	if len(got) != 1 || got[0].Category != "admin" {
		t.Fatal("expected admin finding")
	}
}

func TestAdminDetectorNegative(t *testing.T) {
	d := AdminDetector{}
	got := d.Detect([]string{"https://example.com/api/users"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
