// Package scanner is the V1 pipeline entry point.
//
// V1 pipeline: Collector -> Decoder -> Rule -> Entropy -> Verifier -> Confidence -> Reporter.
// The legacy V6 entry points (ScanPaths, ScanFile, ScanReader, ScanURLs, ScanContent) are preserved
// alongside the new Pipeline type.
package scanner

import (
	"regexp"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type Config struct {
	Workers         int
	MaxFileSize     int64
	Exclude         *regexp.Regexp
	Rules           *rules.RuleSet
	MinSeverity     finding.Severity
	NoDedup         bool
	Debug           bool
	DecodeBase64    bool
	DecodeHex       bool
	DecodeUnicode   bool
	DecodeURL       bool
	DecodeGzip      bool
	JSReconstruct   bool
	Endpoints       bool
	DowngradeFP     bool
	URLs            []string
	URLFile         string
	Scope           *regexp.Regexp
	CrawlLimit      int
	CrawlDepth      int
	Headless        bool
	RateLimit       int
	UserAgent       string
	Cookies         bool
	CookieFile      string
	Concurrency     int
	HostConcurrency int
	RespectRobots   bool
	GitHistory      bool
	MaxScanLineLen  int                              // skip per-line scanning on lines exceeding this length (0=unlimited)
	Progress        func(filesScanned, findings int) // optional callback fired per scanned file; nil = no-op
}
