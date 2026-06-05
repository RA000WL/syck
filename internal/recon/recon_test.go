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

func TestRegistryAllDetectors(t *testing.T) {
	r := NewRegistry()
	r.Register(GraphQLDetector{})
	r.Register(SwaggerDetector{})
	r.Register(AdminDetector{})
	r.Register(DebugDetector{})
	r.Register(MetricsDetector{})
	r.Register(InternalDetector{})
	r.Register(StagingDetector{})
	r.Register(StorageDetector{})
	r.Register(AuthDetector{})

	urls := []string{
		"https://example.com/graphql",
		"https://example.com/swagger.json",
		"https://example.com/admin/users",
		"https://example.com/debug",
		"https://example.com/metrics",
		"https://corp.example.com/internal",
		"https://staging.example.com/",
		"https://mybucket.s3.amazonaws.com/data",
		"https://example.com/oauth/token",
	}
	got := r.Detect(urls)
	if len(got) != 9 {
		t.Errorf("Detect returned %d, want 9 (one per URL)", len(got))
	}
}
