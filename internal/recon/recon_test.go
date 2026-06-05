package recon

import (
	"testing"
)

func TestRegistryEmpty(t *testing.T) {
	r := NewRegistry()
	got := r.Detect(nil)
	if len(got) != 0 {
		t.Errorf("Detect(nil) returned %d, want 0", len(got))
	}
}

func TestRegistryWithStubDetector(t *testing.T) {
	r := NewRegistry()
	r.Register(stubDetector{})
	got := r.Detect([]string{"https://example.com/admin"})
	if len(got) != 1 {
		t.Errorf("Detect returned %d, want 1", len(got))
	}
	if got[0].Category != "stub" {
		t.Errorf("Category = %q, want stub", got[0].Category)
	}
}

type stubDetector struct{}

func (stubDetector) Detect(urls []string) []SurfaceFinding {
	return []SurfaceFinding{{Category: "stub", URL: urls[0]}}
}
