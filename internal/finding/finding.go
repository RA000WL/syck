package finding

import (
	"sort"
	"strconv"
	"strings"
)

const MaxContextLen = 500

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
	if sev, ok := SeverityFromName[strings.ToUpper(s)]; ok {
		return sev
	}
	return SeverityLow
}

type Finding struct {
	File                string
	Line                int
	Column              int
	RuleName            string
	RuleNames           []string `json:"rule_names,omitempty"`
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
	AdaptiveModifier    int    `json:"adaptive_modifier,omitempty"`
	LearningTier        string `json:"learning_tier,omitempty"`
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

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func DeduplicateBySecret(findings []Finding) []Finding {
	// Group key is unchanged: Secret + File. Within each group, emit one
	// finding per distinct occurrence (File+Line+Column) so line info is
	// preserved. RuleName stays a single exact rule name (the highest
	// severity rule at that occurrence); RuleNames carries all rule names
	// at the occurrence sorted by severity desc, then name asc.
	type occurrence struct {
		rep       Finding
		sevByRule map[string]Severity
	}
	byGroup := make(map[string]map[string]*occurrence)

	occKey := func(f Finding) string {
		return f.Secret + "\x00" + f.File
	}
	locKey := func(f Finding) string {
		return f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + strconv.Itoa(f.Column)
	}

	var groupOrder []string
	locOrder := make(map[string][]string)
	for _, f := range findings {
		gk := occKey(f)
		lk := locKey(f)
		bucket, ok := byGroup[gk]
		if !ok {
			bucket = make(map[string]*occurrence)
			byGroup[gk] = bucket
			groupOrder = append(groupOrder, gk)
		}
		occ, ok := bucket[lk]
		if !ok {
			rep := f
			occ = &occurrence{rep: rep, sevByRule: make(map[string]Severity)}
			bucket[lk] = occ
			locOrder[gk] = append(locOrder[gk], lk)
		}
		if sev, seen := occ.sevByRule[f.RuleName]; !seen || severityRank(f.Severity) > severityRank(sev) {
			occ.sevByRule[f.RuleName] = f.Severity
		}
	}

	var result []Finding
	for _, gk := range groupOrder {
		for _, lk := range locOrder[gk] {
			occ := byGroup[gk][lk]
			names := make([]string, 0, len(occ.sevByRule))
			for name := range occ.sevByRule {
				names = append(names, name)
			}
			sort.Slice(names, func(i, j int) bool {
				ri, rj := severityRank(occ.sevByRule[names[i]]), severityRank(occ.sevByRule[names[j]])
				if ri != rj {
					return ri > rj
				}
				return names[i] < names[j]
			})
			out := occ.rep
			out.RuleName = names[0]
			out.RuleNames = names
			out.Severity = occ.sevByRule[names[0]]
			result = append(result, out)
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].File != result[j].File {
			return result[i].File < result[j].File
		}
		if result[i].Line != result[j].Line {
			return result[i].Line < result[j].Line
		}
		return result[i].Column < result[j].Column
	})

	return result
}
