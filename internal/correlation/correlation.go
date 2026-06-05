package correlation

import (
	"sync"

	"github.com/RA000WL/syck/internal/finding"
)

type Detector interface {
	Match(findings []finding.Finding) []CorrelatedFinding
}

type CorrelatedFinding struct {
	Type        string
	Confidence  string
	Components  []finding.Finding
	File        string
	Line        int
	Description string
}

type Correlator struct {
	mu        sync.RWMutex
	detectors []Detector
}

func NewCorrelator() *Correlator {
	return &Correlator{}
}

func (c *Correlator) RegisterDetector(d Detector) {
	if d == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detectors = append(c.detectors, d)
}

func (c *Correlator) Correlate(findings []finding.Finding) []CorrelatedFinding {
	c.mu.RLock()
	detectors := make([]Detector, len(c.detectors))
	copy(detectors, c.detectors)
	c.mu.RUnlock()

	var out []CorrelatedFinding
	for _, d := range detectors {
		out = append(out, d.Match(findings)...)
	}
	return out
}
