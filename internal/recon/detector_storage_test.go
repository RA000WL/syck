package recon

import "testing"

func TestStorageDetectorPositive(t *testing.T) {
	d := StorageDetector{}
	got := d.Detect([]string{"https://mybucket.s3.amazonaws.com/secret"})
	if len(got) == 0 || got[0].Category != "storage" {
		t.Fatal("expected storage finding")
	}
}

func TestStorageDetectorNegative(t *testing.T) {
	d := StorageDetector{}
	got := d.Detect([]string{"https://example.com/index.html"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
