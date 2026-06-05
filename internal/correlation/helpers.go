package correlation

import "github.com/RA000WL/syck/internal/finding"

func matchPair(findings []finding.Finding, nameA, nameB, pairType string, maxSpan int) []CorrelatedFinding {
	var out []CorrelatedFinding
	for i, a := range findings {
		if a.RuleName != nameA {
			continue
		}
		for j, b := range findings {
			if b.RuleName != nameB {
				continue
			}
			if i == j {
				continue
			}
			if a.File != b.File {
				continue
			}
			span := a.Line - b.Line
			if span < 0 {
				span = -span
			}
			if span > maxSpan {
				continue
			}
			out = append(out, CorrelatedFinding{
				Type:        pairType,
				Confidence:  "VERY_HIGH",
				Components:  []finding.Finding{a, b},
				File:        a.File,
				Line:        a.Line,
				Description: nameA + " + " + nameB + " found within " + itoa(span) + " lines",
			})
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
