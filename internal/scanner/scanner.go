// Package scanner is the entry point for all scanning in syck.
//
// # Active path
//
// The CLI (cmd/), the LSP server (internal/lsp), and git-history scanning
// (internal/gitscan) are served by the V6 orchestration entry points:
// ScanPaths, ScanFile, ScanReader, ScanURLs, and ScanContent. These compose
// the live scan path. New scan work should extend this path, not route around
// it.
//
// cmd/ calls ScanPaths (file arguments), ScanURLs (target URLs and piped URLs),
// and ScanContent (piped raw content) directly; ScanFile is reached through
// ScanPaths. ScanReader is exported as part of the same set but currently has
// no non-test caller.
//
// # Pipeline and the stage_* types
//
// Pipeline (pipeline.go) and the stage_* types are a second, explicitly staged
// decomposition of the same work: Collector -> Decoder -> Rule -> Entropy ->
// Correlation -> Verifier -> Confidence -> Reporter. Pipeline is not on the CLI
// path. Its only constructor, NewPipeline, is called solely from
// pipeline_test.go, and no stage constructor has a non-test caller outside
// NewPipeline.
//
// The stages are not uniformly redundant with the active path, so their status
// is recorded here rather than assumed:
//
//   - CorrelationStage is the only route to internal/correlation. Nothing
//     outside NewPipeline constructs a Correlator, so the correlation detectors
//     do not run on the CLI path at all.
//   - VerifierStage performs live secret validation via internal/validator and
//     stamps VerificationStatus unconditionally. The CLI performs the same
//     validation and sets the same states, but only behind the --validate and
//     --verify flags (see cmd/scan_run.go), so this capability is duplicated
//     rather than missing.
//
// Pipeline is exported and remains a supported way to run the staged pipeline.
// This comment describes what these types are and where they run; it does not
// recommend removing them, and their disposition remains an open question. It
// does mean new CLI scan work should not be wired through them without first
// deciding what happens to the two gaps above.
package scanner

import (
	"regexp"
	"time"

	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

type Config struct {
	Workers            int
	MaxFileSize        int64
	Exclude            *regexp.Regexp
	Rules              *rules.RuleSet
	MinSeverity        finding.Severity
	MultiLine          bool // enable multi-line pattern matching (sliding window)
	MinEndpointScore   int  // 0-10; only show endpoints with score >= this
	ProbeJuicyFiles    bool // enable juicy file probing after BFS
	NoDedup            bool
	Debug              bool
	DecodeBase64       bool
	DecodeHex          bool
	DecodeUnicode      bool
	DecodeURL          bool
	DecodeGzip         bool
	DecodeBase64URL    bool
	DecodeJWT          bool
	DecodeDoubleBase64 bool
	DecodeCharCode     bool
	JSReconstruct      bool
	Endpoints          bool
	DowngradeFP        bool
	URLs               []string
	URLFile            string
	Scope              *regexp.Regexp
	CrawlLimit         int
	CrawlDepth         int
	Headless           bool
	RateLimit          int
	UserAgent          string
	Cookies            bool
	CookieFile         string
	Concurrency        int
	HostConcurrency    int
	RespectRobots      bool
	GitHistory         bool
	MaxScanLineLen     int                                                     // skip per-line scanning on lines exceeding this length (0=unlimited)
	Progress           func(filesScanned, findings int)                        // optional callback fired per scanned file; nil = no-op
	URLProgress        func(url string, findings []finding.Finding, done bool) // optional callback for URL scanning mode
	ScanArchives       bool                                                    // extract and scan inside archives (zip, tar, tar.gz, jar, war, ear)
	ScanBinaries       bool                                                    // extract and scan strings from binary files
	StripComments      bool                                                    // strip comment lines before scanning
	DetectAuthHeaders  bool                                                    // detect hardcoded Authorization headers, Bearer tokens, Basic auth, API keys
	ProbeGraphQL       bool                                                    // probe GraphQL endpoints with introspection query
	ParseOpenAPI       bool                                                    // parse OpenAPI/Swagger specs and inject discovered endpoints
	EntropyThresholds  map[string]float64                                      `json:"entropy_thresholds,omitempty"` // per-alphabet entropy threshold overrides
	CacheDB            string                                                  // path to SQLite cache database for cross-run dedup
	Adaptive           bool                                                    // enable adaptive confidence learning
	AdaptiveWeights    *adaptive.LearnedWeightStore                            // loaded weights (nil if not adaptive)

	// Phase 1: Bug bounty core
	HTTPTimeout     time.Duration       // HTTP client timeout for all requests (default 10s)
	ProxyURL        string              // HTTP proxy URL for all requests
	Headers         map[string][]string // custom headers to inject into crawl requests
	ScopePatterns   []*regexp.Regexp    // compiled scope patterns from --scope-file
	Diff            bool                // only output new findings (requires CacheDB)
	CookieString    string              // cookie string to inject (name=value; name2=value2)
	NoSitemap       bool                // disable robots/sitemap discovery
	AllowPrivateIPs bool                // allow secondary fetches/redirects to private IPs (SSRF gate escape hatch)
	HeaderCheck     bool                // analyze HTTP security headers on discovered URLs
	TechDetect      bool                // detect technologies from HTTP responses and source code
	URLCacheDB      string              // path to SQLite URL cache database for cross-run dedup
	ExcludeDir      *regexp.Regexp      // regex to exclude directories during file walking
}
