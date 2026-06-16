package jsanalysis

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	// Environment variable access patterns
	envVarRE        = regexp.MustCompile(`process\.env\.([A-Z_][A-Z0-9_]*)`)
	importMetaEnvRE = regexp.MustCompile(`import\.meta\.env\.([A-Z_][A-Z0-9_]*)`)
	envDollarRE     = regexp.MustCompile(`\$([A-Z_][A-Z0-9_]*)\b`)
	envBracketSingleRE = regexp.MustCompile(`process\.env\['([A-Z_][A-Z0-9_]*)'\]`)
	envBracketDoubleRE = regexp.MustCompile(`process\.env\["([A-Z_][A-Z0-9_]*)"\]`)

	// Dynamic imports and lazy loading - separate patterns for each quote type
	dynamicImportSingleRE = regexp.MustCompile(`import\s*\(\s*'([^']+)'\s*\)`)
	dynamicImportDoubleRE = regexp.MustCompile(`import\s*\(\s*"([^"]+)"\s*\)`)
	dynamicImportBacktickRE = regexp.MustCompile("import\\s*\\(\\s*`([^`]+)`\\s*\\)")
	requireSingleRE   = regexp.MustCompile(`require\s*\(\s*'([^']+)'\s*\)`)
	requireDoubleRE   = regexp.MustCompile(`require\s*\(\s*"([^"]+)"\s*\)`)
	lazyLoadSingleRE  = regexp.MustCompile(`(?i)(?:load|lazy|preload)\s*\(\s*'([^']+)'\s*\)`)
	lazyLoadDoubleRE  = regexp.MustCompile(`(?i)(?:load|lazy|preload)\s*\(\s*"([^"]+)"\s*\)`)

	// Webpack/Vite chunk patterns
	webpackChunkRE   = regexp.MustCompile(`(?:webpackChunk|webpackJsonp|__webpack_require__|webpack_modules)\b`)
	viteChunkRE      = regexp.MustCompile(`(?:(?:__vite_|vite客户端|vite/client)[\w.]*)`)
	chunkImportRE    = regexp.MustCompile(`import\s*\(\s*['"]([^'"]*chunk[^'"]*\.js)['"]\s*\)`)

	// Comment-leaked secrets and endpoints
	lineCommentRE    = regexp.MustCompile(`//\s*(https?://[^\s'"]+)`)
	blockCommentRE   = regexp.MustCompile(`/\*([^*]|\*[^/])*\*/`)
	todoCommentRE    = regexp.MustCompile(`(?i)(?:TODO|FIXME|HACK|XXX|TEMP)\s*[:;]\s*(.+)`)

	// Base64 encoded strings (potential secrets/URLs)
	base64StringRE   = regexp.MustCompile(`['"` + "`" + `]([A-Za-z0-9+/]{40,}={0,2})['"` + "`" + `]`)

	// Config objects with interesting values
	configURLRE      = regexp.MustCompile(`(?i)(?:baseURL|apiURL|api_url|endpoint|baseUrl|host|server|origin)\s*[:=]\s*['"]([^'"]+)['"]`)
	configKeyRE      = regexp.MustCompile(`(?i)(?:apiKey|api_key|token|secret|password|auth)\s*[:=]\s*['"]([^'"]+)['"]`)

	// Internal/hidden service patterns
	internalServiceRE = regexp.MustCompile(`(?i)(?:internal|private|corp|intranet|staging|dev|sandbox|test)\s*[:=]\s*['"]([^'"]+)['"]`)
	localhostRE       = regexp.MustCompile(`(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+`)

	// Sensitive file references
	sensitiveFileRE   = regexp.MustCompile(`['"]([^'"]*(?:\.env|\.key|\.pem|\.cert|\.p12|\.pfx|\.jks|\.keystore|credentials?\.json|secrets?\.json|service[_-]?account)[^'"]*)['"]`)

	// Debug/development URLs
	debugURLRE        = regexp.MustCompile(`(?i)['"]([^'"]*(?:debug|trace|profile|inspect|devtools|console)[^'"]*)['"]`)

	// Source map references
	sourceMapRE       = regexp.MustCompile(`(?:sourceMappingURL|sourceURL)\s*[:=]\s*['"]?([^'"\s]+\.map)['"]?`)

	// API versioning patterns
	apiVersionRE      = regexp.MustCompile(`['"]([^'"]*/(?:v\d+|api/v\d+|version/\d+)[^'"]*)['"]`)

	// Hidden routes/paths in code
	hiddenRouteRE     = regexp.MustCompile(`(?i)(?:route|path|redirect|forward)\s*[:=]\s*['"]([^'"]+/[^'"]+)['"]`)
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
	Value    string
	Context  string
	Type     string // "env_ref", "config_secret", "base64", "comment_leak"
	Line     int
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
			result.InternalURLs = appendUnique(result.InternalURLs, m[0])
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
