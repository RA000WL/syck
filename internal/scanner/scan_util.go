package scanner

import (
	"bufio"
	"github.com/RA000WL/syck/internal/confidence"
	"github.com/RA000WL/syck/internal/decoder"
	"github.com/RA000WL/syck/internal/entropy"
	"github.com/RA000WL/syck/internal/fileutil"
	"github.com/RA000WL/syck/internal/finding"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const maxEndpointBuf = 10 << 20

// stdinScanBufferBytes is ScanReader's one-shot buffer. It is NOT pooled:
// ScanReader runs once per invocation, so a fresh 10MB allocation per call is
// cheaper than the fallback path it protects against, and it preserves the
// pre-Batch-3 capability of handling stdin lines up to 10MB (minified JS).
const stdinScanBufferBytes = 10 << 20

var streamingBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 256<<10)
		return &b
	},
}

var textExtensions = fileutil.TextExtensions

var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "__pycache__": true,
	"node_modules": true, ".venv": true, "venv": true, "env": true,
	".tox": true, ".eggs": true, "eggs": true, ".mypy_cache": true,
	".pytest_cache": true, ".cache": true, "target": true, "build": true,
	"dist": true, ".next": true, ".nuxt": true, ".output": true,
	"vendor": true, ".bundle": true, ".gradle": true, "bin": true,
	"obj": true, ".terraform": true, ".serverless": true,
}

func isTextFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, 512)
	n, err := reader.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	buf = buf[:n]

	for _, b := range buf {
		if b == 0 {
			return false
		}
	}
	return true
}

// baseOf returns the scheme+host portion of a URL.
func baseOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func checkEntropyToken(tok string, thresholds map[string]float64) (bool, float64) {
	if !entropy.IsEntropyTokenMatch(tok) {
		return false, 0
	}
	if len(thresholds) == 0 {
		return true, entropy.Shannon(tok)
	}
	a := entropy.DetectAlphabet(tok)
	alphaName := a.String()
	if override, ok := thresholds[alphaName]; ok {
		e := entropy.EntropyByAlphabet(tok, a)
		return e >= override, e
	}
	return true, entropy.Shannon(tok)
}

func confidenceBandFromScore(score int) string {
	switch {
	case score >= 95:
		return "CRITICAL"
	case score >= 80:
		return "HIGH"
	case score >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// FilterNewOnly returns only findings marked as new (IsNew == true).
func FilterNewOnly(findings []finding.Finding) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		if f.IsNew {
			result = append(result, f)
		}
	}
	return result
}

func contextLabel(tagPrefix string) string {
	switch tagPrefix {
	case "archive_":
		return "archive: "
	case "binary_":
		return "binary: "
	default:
		return "gzip decoded: "
	}
}

var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)

// ScanExpiredJWTs finds expired JWTs in text and returns findings.
func ScanExpiredJWTs(line string, lineNum int, path string) []finding.Finding {
	var findings []finding.Finding
	for _, m := range jwtRe.FindAllString(line, -1) {
		if decoder.IsJWTExpired(m) {
			col := strings.Index(line, m)
			if col < 0 {
				col = 0
			}
			findings = append(findings, finding.Finding{
				File:            path,
				Line:            lineNum,
				Column:          col,
				RuleName:        "expired_jwt_token",
				Severity:        finding.SeverityHigh,
				Secret:          m,
				Context:         finding.Truncate(strings.TrimSpace(line)),
				Entropy:         0,
				Confidence:      confidence.PtsRegex,
				ConfidenceBand:  confidence.Band(confidence.PtsRegex),
				DetectionMethod: "regex+expiry",
			})
		}
	}
	return findings
}
