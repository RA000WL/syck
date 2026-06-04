package finding

import "sort"

type Severity int

const (
	SeverityInfo     Severity = 0
	SeverityLow      Severity = 1
	SeverityMedium   Severity = 2
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

var SeverityNames = map[Severity]string{
	SeverityInfo:     "INFO",
	SeverityLow:      "LOW",
	SeverityMedium:   "MEDIUM",
	SeverityHigh:     "HIGH",
	SeverityCritical: "CRITICAL",
}

var SeverityFromName = map[string]Severity{
	"INFO":     SeverityInfo,
	"LOW":      SeverityLow,
	"MEDIUM":   SeverityMedium,
	"HIGH":     SeverityHigh,
	"CRITICAL": SeverityCritical,
}

func ParseSeverity(s string) Severity {
	if sev, ok := SeverityFromName[s]; ok {
		return sev
	}
	return SeverityLow
}

type Finding struct {
	File      string
	Line      int
	Column    int
	RuleName  string
	Severity  Severity
	Secret    string
	Context   string
	Entropy   float64
}

type Summary struct {
	FilesWithFindings int
	TotalFindings     int
	BySeverity        map[Severity]int
}

func BuildSummary(findings []Finding) Summary {
	s := Summary{
		BySeverity: make(map[Severity]int),
	}
	files := make(map[string]bool)
	for _, f := range findings {
		s.TotalFindings++
		s.BySeverity[f.Severity]++
		files[f.File] = true
	}
	s.FilesWithFindings = len(files)
	return s
}

func SeverityOrder(sevs []Severity) {
	sort.Slice(sevs, func(i, j int) bool {
		return sevs[i] > sevs[j]
	})
}

func Deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		key := f.RuleName + ":" + f.Secret + ":" + f.File
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}
