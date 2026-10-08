package jsanalysis

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The loopback host vocabulary localhostRE recognizes, as a pattern fragment
// rather than a compiled regexp, because it is assembled into two patterns.
//
//	loopbackOctet  one decimal IPv4 octet, 0-255, no leading zeros
//	loopbackHost  the name in any case, all of 127/8 as dotted quads,
//	              the unspecified address, and bracketed ::1
//
// The octets are bounded deliberately. An unbounded \d{1,3} would also accept
// "127.300.1.1:8080", which is not an address and not loopback; the bound is
// what keeps the widened vocabulary from inventing findings.
const (
	loopbackOctet = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	loopbackHost  = `(?:localhost|127\.` + loopbackOctet + `(?:\.` + loopbackOctet + `){2}|0\.0\.0\.0|\[::1\])`
)

var (
	// Environment variable access patterns
	envVarRE           = regexp.MustCompile(`process\.env\.([A-Z_][A-Z0-9_]*)`)
	importMetaEnvRE    = regexp.MustCompile(`import\.meta\.env\.([A-Z_][A-Z0-9_]*)`)
	envDollarRE        = regexp.MustCompile(`\$([A-Z_][A-Z0-9_]*)\b`)
	envBracketSingleRE = regexp.MustCompile(`process\.env\['([A-Z_][A-Z0-9_]*)'\]`)
	envBracketDoubleRE = regexp.MustCompile(`process\.env\["([A-Z_][A-Z0-9_]*)"\]`)

	// Dynamic imports and lazy loading - separate patterns for each quote type
	dynamicImportSingleRE   = regexp.MustCompile(`import\s*\(\s*'([^']+)'\s*\)`)
	dynamicImportDoubleRE   = regexp.MustCompile(`import\s*\(\s*"([^"]+)"\s*\)`)
	dynamicImportBacktickRE = regexp.MustCompile("import\\s*\\(\\s*`([^`]+)`\\s*\\)")
	requireSingleRE         = regexp.MustCompile(`require\s*\(\s*'([^']+)'\s*\)`)
	requireDoubleRE         = regexp.MustCompile(`require\s*\(\s*"([^"]+)"\s*\)`)
	lazyLoadSingleRE        = regexp.MustCompile(`(?i)(?:load|lazy|preload)\s*\(\s*'([^']+)'\s*\)`)
	lazyLoadDoubleRE        = regexp.MustCompile(`(?i)(?:load|lazy|preload)\s*\(\s*"([^"]+)"\s*\)`)

	// Webpack/Vite chunk patterns
	webpackChunkRE = regexp.MustCompile(`(?:webpackChunk|webpackJsonp|__webpack_require__|webpack_modules)\b`)
	viteChunkRE    = regexp.MustCompile(`(?:(?:__vite_|vite客户端|vite/client)[\w.]*)`)
	chunkImportRE  = regexp.MustCompile(`import\s*\(\s*['"]([^'"]*chunk[^'"]*\.js)['"]\s*\)`)

	// Comment-leaked secrets and endpoints
	lineCommentRE  = regexp.MustCompile(`//\s*(https?://[^\s'"]+)`)
	blockCommentRE = regexp.MustCompile(`/\*([^*]|\*[^/])*\*/`)
	todoCommentRE  = regexp.MustCompile(`(?i)(?:TODO|FIXME|HACK|XXX|TEMP)\s*[:;]\s*(.+)`)

	// Base64 encoded strings (potential secrets/URLs)
	base64StringRE = regexp.MustCompile(`['"` + "`" + `]([A-Za-z0-9+/]{40,}={0,2})['"` + "`" + `]`)

	// Config objects with interesting values
	configURLRE = regexp.MustCompile(`(?i)(?:baseURL|apiURL|api_url|endpoint|baseUrl|host|server|origin)\s*[:=]\s*['"]([^'"]+)['"]`)
	configKeyRE = regexp.MustCompile(`(?i)(?:apiKey|api_key|token|secret|password|auth)\s*[:=]\s*['"]([^'"]+)['"]`)

	// Internal/hidden service patterns
	internalServiceRE = regexp.MustCompile(`(?i)(?:internal|private|corp|intranet|staging|dev|sandbox|test)\s*[:=]\s*['"]([^'"]+)['"]`)

	// localhostRE extracts loopback service addresses — a loopback host token
	// immediately followed by :port — from raw JS source. It is deliberately NOT
	// delegated to internalurl.IsLoopback. Batch 10 (ARCHITECTURE.md section 15
	// item 3) fixed the two properties that used to block the swap; the residue
	// is recorded here so it does not have to be re-derived.
	//
	// WHAT THE FIX CHANGED. The pattern used to be unanchored, case-sensitive,
	// and three spellings wide:
	//
	//	(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+
	//
	// which carved a SUBSPAN out of a longer host: "http://my-localhost:8080/"
	// produced the finding "localhost:8080" — a string that is not a host, and
	// one IsLoopback answers false for. Vocabulary and anchoring were widened in
	// the same edit, because a widened token list on an unanchored pattern trades
	// under-matches for wrong findings and still never emits a whole host:
	//
	//  - ANCHORED. The match begins at the start of the line or after a
	//    character that cannot occur inside a host token ([^A-Za-z0-9._-]), and
	//    it consumes any host labels preceding the loopback token instead of
	//    skipping them, so the finding is the whole host the author typed:
	//    "my-localhost:8080", never the carved "localhost:8080". A loopback token
	//    that is not the final label of its host ("localhost.example.com:8080")
	//    no longer matches at all, for the same reason.
	//  - WIDENED. "localhost" in any case, all of 127/8 as dotted quads,
	//    "0.0.0.0" and bracketed "[::1]" (see loopbackHost). The :port
	//    requirement and the port shape are unchanged: :port is what makes this
	//    a service-address finding rather than a bare hostname, so a portless
	//    "localhost" stays out.
	//
	// Note the boundary class is a character class, not \b. \b would NOT have
	// fixed the carve-up: both "-" and "." are non-word characters, so \b
	// happily matches at the seam in "my-localhost" and "foo.localhost".
	//
	// The prefix group is (?:[A-Za-z0-9_-]*[.-])* — zero or more labels each
	// followed by a separator. The zero-width case is load-bearing: a leading
	// separator (".localhost:8080") is part of the host token the author typed,
	// and dropping it would lose that finding rather than widen it.
	//
	// DELEGATION IS CLOSER, AND STILL NOT DONE. Emitting whole hosts removes the
	// reason Batch 5 recorded for refusing the swap, but not every reason.
	// IsLoopback parses a host and answers false for hosts this extractor
	// deliberately reports whole — "my-localhost", "foo.localhost" — so
	// delegating would DROP those findings; and IsLoopback accepts spellings
	// this extractor has no reason to emit (portless "localhost", "127.1",
	// "2130706433", a zoned "[::1%25lo]"), so delegating would also ADD
	// findings. It would still need a host:port tokenizer to find candidate
	// tokens, so this regex does not disappear — only its vocabulary half
	// would. That makes delegation its own CHANGELOG'd decision, not a cleanup.
	//
	// TRIPWIRE: do not read Batch 10 as unblocking the swap. Batch 5's condition
	// — "re-evaluate delegation once this extractor emits whole hosts" — is now
	// MET, which is precisely why the answer is written down instead of left
	// implied: it is still NO, for the two deltas above. Revisit when a change is
	// prepared to accept them and CHANGELOG them, or when a caller wants a
	// classifier rather than an extractor, in which case internal/recon's
	// classifyInternal — which already consumes IsLoopback over whole URLs — is
	// the model to copy. A change to IsLoopback's vocabulary alone is still not
	// a reason to revisit. TestLocalhostRE_SixInputs pins this package's output;
	// it does not check the predicate's answer, so it will not catch a delegation
	// in either direction.
	localhostRE = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9._-])((?:[A-Za-z0-9_-]*[.-])*` + loopbackHost + `:\d+)`)

	// Sensitive file references
	sensitiveFileRE = regexp.MustCompile(`['"]([^'"]*(?:\.env|\.key|\.pem|\.cert|\.p12|\.pfx|\.jks|\.keystore|credentials?\.json|secrets?\.json|service[_-]?account)[^'"]*)['"]`)

	// Debug/development URLs
	debugURLRE = regexp.MustCompile(`(?i)['"]([^'"]*(?:debug|trace|profile|inspect|devtools|console)[^'"]*)['"]`)

	// Source map references
	sourceMapRE = regexp.MustCompile(`(?:sourceMappingURL|sourceURL)\s*[:=]\s*['"]?([^'"\s]+\.map)['"]?`)

	// API versioning patterns
	apiVersionRE = regexp.MustCompile(`['"]([^'"]*/(?:v\d+|api/v\d+|version/\d+)[^'"]*)['"]`)

	// Hidden routes/paths in code
	hiddenRouteRE = regexp.MustCompile(`(?i)(?:route|path|redirect|forward)\s*[:=]\s*['"]([^'"]+/[^'"]+)['"]`)
)

type AnalysisResult struct {
	// Environment variables found
	EnvVars []string
	// Hidden endpoints/URLs discovered
	Endpoints []string
	// Secrets or sensitive values found
	Secrets []SecretFinding
	// Internal URLs found
	InternalURLs []string
	// Debug/development artifacts
	DebugArtifacts []string
	// Source map references
	SourceMaps []string
	// Sensitive file references
	SensitiveFiles []string
	// Webpack/Vite chunk info
	Chunks []string
	// Comments that may leak info
	LeakedComments []string
}

type SecretFinding struct {
	Value   string
	Context string
	Type    string // "env_ref", "config_secret", "base64", "comment_leak"
	Line    int
}

func AnalyzeJS(content string, filePath string) *AnalysisResult {
	result := &AnalysisResult{}
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		lineNum++

		// Environment variable references
		for _, m := range envVarRE.FindAllStringSubmatch(line, -1) {
			result.EnvVars = appendUnique(result.EnvVars, m[1])
		}
		for _, m := range importMetaEnvRE.FindAllStringSubmatch(line, -1) {
			result.EnvVars = appendUnique(result.EnvVars, "IMPORT_META_"+m[1])
		}
		for _, m := range envBracketSingleRE.FindAllStringSubmatch(line, -1) {
			result.EnvVars = appendUnique(result.EnvVars, m[1])
		}
		for _, m := range envBracketDoubleRE.FindAllStringSubmatch(line, -1) {
			result.EnvVars = appendUnique(result.EnvVars, m[1])
		}

		// Dynamic imports
		for _, re := range []*regexp.Regexp{dynamicImportSingleRE, dynamicImportDoubleRE, dynamicImportBacktickRE} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				result.Endpoints = appendUnique(result.Endpoints, m[1])
			}
		}
		for _, re := range []*regexp.Regexp{requireSingleRE, requireDoubleRE} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				if strings.Contains(m[1], "/") || strings.HasPrefix(m[1], ".") {
					result.Endpoints = appendUnique(result.Endpoints, m[1])
				}
			}
		}

		// Webpack/Vite chunks
		if webpackChunkRE.MatchString(line) {
			for _, m := range chunkImportRE.FindAllStringSubmatch(line, -1) {
				result.Chunks = appendUnique(result.Chunks, m[1])
			}
		}
		if viteChunkRE.MatchString(line) {
			for _, m := range chunkImportRE.FindAllStringSubmatch(line, -1) {
				result.Chunks = appendUnique(result.Chunks, m[1])
			}
		}

		// Comment-leaked URLs
		for _, m := range lineCommentRE.FindAllStringSubmatch(line, -1) {
			result.LeakedComments = appendUnique(result.LeakedComments, m[1])
		}

		// TODO/FIXME with potential secrets
		for _, m := range todoCommentRE.FindAllStringSubmatch(line, -1) {
			todoText := strings.TrimSpace(m[1])
			if strings.Contains(todoText, "key") || strings.Contains(todoText, "token") ||
				strings.Contains(todoText, "secret") || strings.Contains(todoText, "password") {
				result.Secrets = append(result.Secrets, SecretFinding{
					Value:   todoText,
					Context: "TODO/FIXME comment",
					Type:    "comment_leak",
					Line:    lineNum,
				})
			}
		}

		// Base64 encoded strings
		for _, m := range base64StringRE.FindAllStringSubmatch(line, -1) {
			decoded := tryDecodeBase64(m[1])
			if decoded != "" && (strings.Contains(decoded, "http") || strings.Contains(decoded, "key") ||
				strings.Contains(decoded, "token") || strings.Contains(decoded, "secret")) {
				result.Secrets = append(result.Secrets, SecretFinding{
					Value:   m[1],
					Context: "base64 decoded: " + decoded,
					Type:    "base64",
					Line:    lineNum,
				})
			}
		}

		// Config URLs
		for _, m := range configURLRE.FindAllStringSubmatch(line, -1) {
			result.Endpoints = appendUnique(result.Endpoints, m[1])
		}

		// Config secrets
		for _, m := range configKeyRE.FindAllStringSubmatch(line, -1) {
			val := m[1]
			if len(val) > 5 && val != "xxx" && val != "your_key_here" && val != "CHANGE_ME" {
				result.Secrets = append(result.Secrets, SecretFinding{
					Value:   val,
					Context: strings.TrimSpace(line),
					Type:    "config_secret",
					Line:    lineNum,
				})
			}
		}

		// Internal service URLs
		for _, m := range internalServiceRE.FindAllStringSubmatch(line, -1) {
			result.InternalURLs = appendUnique(result.InternalURLs, m[1])
		}
		for _, m := range localhostRE.FindAllStringSubmatch(line, -1) {
			// m[1], not m[0]: when the match is preceded by a host token
			// boundary character, m[0] carries that character and m[1] is the
			// whole host plus port. Emitting m[0] would report a leading quote,
			// slash or space as part of the finding.
			result.InternalURLs = appendUnique(result.InternalURLs, m[1])
		}

		// Sensitive file references
		for _, m := range sensitiveFileRE.FindAllStringSubmatch(line, -1) {
			result.SensitiveFiles = appendUnique(result.SensitiveFiles, m[1])
		}

		// Debug URLs
		for _, m := range debugURLRE.FindAllStringSubmatch(line, -1) {
			result.DebugArtifacts = appendUnique(result.DebugArtifacts, m[1])
		}

		// Source maps
		for _, m := range sourceMapRE.FindAllStringSubmatch(line, -1) {
			result.SourceMaps = appendUnique(result.SourceMaps, m[1])
		}

		// API versioning
		for _, m := range apiVersionRE.FindAllStringSubmatch(line, -1) {
			result.Endpoints = appendUnique(result.Endpoints, m[1])
		}

		// Hidden routes
		for _, m := range hiddenRouteRE.FindAllStringSubmatch(line, -1) {
			path := m[1]
			if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
				result.Endpoints = appendUnique(result.Endpoints, path)
			}
		}
	}

	return result
}

func appendUnique(slice []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return slice
	}
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func tryDecodeBase64(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return ""
		}
	}
	result := string(decoded)
	if !utf8.ValidString(result) {
		return ""
	}
	return result
}
