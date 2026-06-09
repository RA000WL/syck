package formatters

import (
	"path/filepath"
	"strings"

	"github.com/RA000WL/syck/internal/finding"
)

type ScanSummary struct {
	FilesWithFindings int            `json:"files_with_findings"`
	TotalFindings     int            `json:"total_findings"`
	SeverityCounts    map[string]int `json:"severity_counts"`
	FileTypeCounts    map[string]int `json:"file_type_counts"`
	RiskScoreDist     map[int]int    `json:"risk_score_distribution,omitempty"`
	NewCount          int            `json:"new_count,omitempty"`
	EndpointCount     int            `json:"endpoint_count,omitempty"`
}

func BuildSummary(findings []finding.Finding) *ScanSummary {
	s := &ScanSummary{
		SeverityCounts: make(map[string]int),
		FileTypeCounts: make(map[string]int),
		RiskScoreDist:  make(map[int]int),
	}
	files := make(map[string]bool)
	for _, f := range findings {
		s.TotalFindings++
		s.SeverityCounts[finding.SeverityNames[f.Severity]]++
		files[f.File] = true

		ext := strings.ToLower(filepath.Ext(f.File))
		if ext == "" {
			ext = "(no ext)"
		}
		s.FileTypeCounts[ext]++

		if f.RiskScore >= 0 {
			s.RiskScoreDist[f.RiskScore]++
		}
		// NOTE: prefix-based detection — add new endpoint rule prefixes here
		if strings.HasPrefix(f.RuleName, "endpoint") || strings.HasPrefix(f.RuleName, "openapi_") || strings.HasPrefix(f.RuleName, "graphql_") {
			s.EndpointCount++
		}
	}
	s.FilesWithFindings = len(files)
	return s
}
