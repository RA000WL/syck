package recon

import "github.com/RA000WL/syck/internal/finding"

type SurfaceFinding struct {
	URL        string
	Category   string
	Severity   finding.Severity
	Confidence int
	Source     string
	Line       int
}

type Detector interface {
	Detect(urls []string) []SurfaceFinding
}

type Registry struct {
	detectors []Detector
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

func (r *Registry) Detect(urls []string) []SurfaceFinding {
	var out []SurfaceFinding
	for _, d := range r.detectors {
		out = append(out, d.Detect(urls)...)
	}
	return out
}
