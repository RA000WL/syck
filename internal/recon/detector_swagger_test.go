package recon

import "testing"

func TestSwaggerDetectorPositive(t *testing.T) {
	d := SwaggerDetector{}
	got := d.Detect([]string{"https://example.com/swagger.json"})
	if len(got) != 1 || got[0].Category != "swagger" {
		t.Fatal("expected swagger finding")
	}
}

func TestSwaggerDetectorNegative(t *testing.T) {
	d := SwaggerDetector{}
	got := d.Detect([]string{"https://example.com/index.html"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}
