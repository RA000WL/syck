// Package scanner is the V1 pipeline entry point.
//
// V1 pipeline: Collector -> Decoder -> Rule -> Entropy -> Verifier -> Confidence -> Reporter.
// The legacy V6 entry points (ScanPaths, ScanFile, ScanReader, ScanURLs, ScanContent) are preserved
// alongside the new Pipeline type.
package scanner

import (
	"regexp"

	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type Config struct {
	Workers           int
	MaxFileSize       int64
	Exclude           *regexp.Regexp
	Rules             *rules.RuleSet
	MinSeverity       finding.Severity
	MultiLine         bool // enable multi-line pattern matching (sliding window)
	MinEndpointScore  int  // 0-10; only show endpoints with score >= this
	ProbeJuicyFiles   bool // enable juicy file probing after BFS
	NoDedup           bool
	Debug             bool
	DecodeBase64      bool
	DecodeHex         bool
	DecodeUnicode     bool
	DecodeURL         bool
	DecodeGzip        bool
	JSReconstruct     bool
	Endpoints         bool
	DowngradeFP       bool
	URLs              []string
	URLFile           string
	Scope             *regexp.Regexp
	CrawlLimit        int
	CrawlDepth        int
	Headless          bool
	RateLimit         int
	UserAgent         string
	Cookies           bool
	CookieFile        string
	Concurrency       int
	HostConcurrency   int
	RespectRobots     bool
	GitHistory        bool
	MaxScanLineLen    int                              // skip per-line scanning on lines exceeding this length (0=unlimited)
	Progress          func(filesScanned, findings int) // optional callback fired per scanned file; nil = no-op
	ScanArchives      bool                             // extract and scan inside archives (zip, tar, tar.gz, jar, war, ear)
	ScanBinaries      bool                             // extract and scan strings from binary files
	StripComments     bool                             // strip comment lines before scanning
	DetectAuthHeaders bool                             // detect hardcoded Authorization headers, Bearer tokens, Basic auth, API keys
	ProbeGraphQL      bool                             // probe GraphQL endpoints with introspection query
	ParseOpenAPI      bool                             // parse OpenAPI/Swagger specs and inject discovered endpoints
	EntropyThresholds map[string]float64               `json:"entropy_thresholds,omitempty"` // per-alphabet entropy threshold overrides
	CacheDB           string                           // path to SQLite cache database for cross-run dedup
	Adaptive          bool                             // enable adaptive confidence learning
	AdaptiveWeights   *adaptive.LearnedWeightStore     // loaded weights (nil if not adaptive)
}
