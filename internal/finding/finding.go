package finding

import "sort"

const MaxContextLen = 500

const (
	ConfidenceRegex    = 60
	ConfidenceEntropy  = 15
	ConfidenceContext  = 15
	ConfidenceDecoded  = 10
	ConfidenceURLParam = 10
)

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
	File                string
	Line                int
	Column              int
	RuleName            string
	Severity            Severity
	RiskScore           int    `json:"risk_score,omitempty"`
	FirstSeen           string `json:"first_seen,omitempty"`
	LastSeen            string `json:"last_seen,omitempty"`
	IsNew               bool   `json:"is_new,omitempty"`
	Secret              string
	Context             string
	ContextBefore       string
	ContextAfter        string
	Entropy             float64
	Confidence          int    `json:"confidence,omitempty"`
	ConfidenceBand      string `json:"confidence_band,omitempty"`
	DetectionMethod     string `json:"detection_method,omitempty"`
	VerificationStatus  string
	DecodedValuePreview string
}

type Summary struct {
	FilesWithFindings int
	TotalFindings     int
	BySeverity        map[Severity]int
}

func BuildBasicSummary(findings []Finding) Summary {
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

func Truncate(s string) string {
	if len(s) > MaxContextLen {
		return s[:MaxContextLen]
	}
	return s
}

func TruncateContext(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200]
}

func Deduplicate(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		ctxPrefix := f.Context
		if len(ctxPrefix) > 40 {
			ctxPrefix = ctxPrefix[:40]
		}
		key := f.RuleName + "\x00" + f.Secret + "\x00" + f.File + "\x00" + ctxPrefix
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}
