// Package sourcemap provides source map parsing and content extraction.
package sourcemap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// SourceMap represents a parsed JavaScript source map
type SourceMap struct {
	Version    int      `json:"version"`
	File       string   `json:"file"`
	SourceRoot string   `json:"sourceRoot"`
	Sources    []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Names      []string `json:"names"`
	Mappings   string   `json:"mappings"`
}

// SourceMapFile represents a file within a source map with its content
type SourceMapFile struct {
	OriginalPath string
	SourceRoot   string
	FullPath     string
	Content      string
	HasContent   bool
}

// SourceMapSecret represents a potential secret found in source map
type SourceMapSecret struct {
	SourceFile string
	Pattern    string
	Reason     string
	Line       int
	Content    string
}

// ParseSourceMap parses a source map JSON string
func ParseSourceMap(content string) (*SourceMap, error) {
	var sm SourceMap
	if err := json.Unmarshal([]byte(content), &sm); err != nil {
		return nil, fmt.Errorf("parse source map: %w", err)
	}
	return &sm, nil
}

// FetchAndParseSourceMap fetches a source map URL and parses it
func FetchAndParseSourceMap(client *http.Client, mapURL string) (*SourceMap, error) {
	req, err := http.NewRequest("GET", mapURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "syck-sourcemap/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, err
	}

	return ParseSourceMap(string(body))
}

// ExtractFiles returns the list of original source files with their content
func (sm *SourceMap) ExtractFiles() []SourceMapFile {
	var files []SourceMapFile
	seen := make(map[string]bool)

	for i, src := range sm.Sources {
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true

		fullPath := src
		if sm.SourceRoot != "" {
			fullPath = sm.SourceRoot + src
		}

		file := SourceMapFile{
			OriginalPath: src,
			SourceRoot:   sm.SourceRoot,
			FullPath:     fullPath,
		}

		// Extract content if available
		if sm.SourcesContent != nil && i < len(sm.SourcesContent) {
			file.Content = sm.SourcesContent[i]
			file.HasContent = file.Content != ""
		}

		files = append(files, file)
	}

	return files
}

// ExtractSecrets scans source map sources for potential secrets
func (sm *SourceMap) ExtractSecrets() []SourceMapSecret {
	var secrets []SourceMapSecret

	// Patterns that might indicate secrets in source files
	secretPatterns := []string{
		"password", "secret", "token", "api_key", "apikey",
		"private_key", "privatekey", "credentials", "auth",
		"access_key", "accesskey", "client_secret", "clientsecret",
	}

	// Code patterns that might contain secrets
	codePatterns := []struct {
		Pattern string
		Reason  string
	}{
		{`password\s*[=:]\s*['"]`, "hardcoded password"},
		{`secret\s*[=:]\s*['"]`, "hardcoded secret"},
		{`token\s*[=:]\s*['"]`, "hardcoded token"},
		{`api[_-]?key\s*[=:]\s*['"]`, "hardcoded API key"},
		{`bearer\s+[A-Za-z0-9\-._~+/]+=*`, "Bearer token"},
		{`eyJ[A-Za-z0-9\-._]+`, "JWT token"},
		{`AKIA[0-9A-Z]{16}`, "AWS access key"},
		{`ghp_[A-Za-z0-9]{36}`, "GitHub personal access token"},
		{`sk_live_[A-Za-z0-9]{24,}`, "Stripe live key"},
		{`sk_test_[A-Za-z0-9]{24,}`, "Stripe test key"},
	}

	for i, src := range sm.Sources {
		srcLower := strings.ToLower(src)

		// Check filename patterns
		for _, pattern := range secretPatterns {
			if strings.Contains(srcLower, pattern) {
				secret := SourceMapSecret{
					SourceFile: src,
					Pattern:    pattern,
					Reason:     fmt.Sprintf("filename contains '%s'", pattern),
				}

				// Add content if available
				if sm.SourcesContent != nil && i < len(sm.SourcesContent) {
					secret.Content = truncateContent(sm.SourcesContent[i], 200)
				}

				secrets = append(secrets, secret)
				break
			}
		}

		// Check code content for secrets
		if sm.SourcesContent != nil && i < len(sm.SourcesContent) {
			content := sm.SourcesContent[i]
			contentLines := strings.Split(content, "\n")

			for lineNum, line := range contentLines {
				for _, cp := range codePatterns {
					if strings.Contains(strings.ToLower(line), strings.ToLower(cp.Pattern)) ||
						strings.Contains(line, cp.Pattern) {
						secrets = append(secrets, SourceMapSecret{
							SourceFile: src,
							Pattern:    cp.Pattern,
							Reason:     cp.Reason,
							Line:       lineNum + 1,
							Content:    strings.TrimSpace(truncateContent(line, 100)),
						})
					}
				}
			}
		}
	}

	return secrets
}

// GetMapURL returns the source map URL from a JavaScript file's sourceMappingURL
func GetMapURL(jsContent string) string {
	// Look for //# sourceMappingURL= or //@ sourceMappingURL=
	lines := strings.Split(jsContent, "\n")
	for i := len(lines) - 1; i >= 0 && i >= len(lines)-5; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "//# sourceMappingURL=") {
			return strings.TrimPrefix(line, "//# sourceMappingURL=")
		}
		if strings.HasPrefix(line, "//@ sourceMappingURL=") {
			return strings.TrimPrefix(line, "//@ sourceMappingURL=")
		}
	}
	return ""
}

// IsSourceMapURL checks if a URL is a source map file
func IsSourceMapURL(url string) bool {
	return strings.HasSuffix(url, ".map") ||
		strings.HasSuffix(url, ".js.map") ||
		strings.Contains(url, ".map?")
}

// DecodeBase64SourceMap decodes a base64-encoded source map (data URL)
func DecodeBase64SourceMap(dataURL string) (*SourceMap, error) {
	// Handle data URL format: data:application/json;base64,...
	if strings.HasPrefix(dataURL, "data:") {
		parts := strings.SplitN(dataURL, ",", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid data URL")
		}

		// Check if base64 encoded
		if strings.Contains(parts[0], "base64") {
			decoded, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, fmt.Errorf("base64 decode: %w", err)
			}
			return ParseSourceMap(string(decoded))
		}

		// Plain data URL
		return ParseSourceMap(parts[1])
	}

	return nil, fmt.Errorf("not a data URL")
}

// VLQDecoder decodes VLQ (Variable-Length Quantity) encoded strings
type VLQDecoder struct {
	integers map[byte]int
}

// NewVLQDecoder creates a new VLQ decoder
func NewVLQDecoder() *VLQDecoder {
	integers := make(map[byte]int)
	for i := 0; i < 64; i++ {
		var c byte
		if i < 26 {
			c = byte('A' + i)
		} else if i < 52 {
			c = byte('a' + i - 26)
		} else if i < 62 {
			c = byte('0' + i - 52)
		} else if i == 62 {
			c = '+'
		} else {
			c = '/'
		}
		integers[c] = i
	}
	return &VLQDecoder{integers: integers}
}

// Decode decodes a VLQ-encoded string to an integer
func (d *VLQDecoder) Decode(s string) (int, int) {
	result := 0
	shift := 0
	i := 0

	for i < len(s) {
		digit, ok := d.integers[s[i]]
		if !ok {
			return 0, i
		}
		i++

		result |= (digit & 31) << shift
		shift += 5

		if digit&32 == 0 {
			break
		}
	}

	// Handle negative numbers
	if result&1 == 1 {
		return -(result >> 1), i
	}
	return result >> 1, i
}

// DecodeMappings decodes the mappings string into source positions
func (sm *SourceMap) DecodeMappings() []Mapping {
	if sm.Mappings == "" {
		return nil
	}

	decoder := NewVLQDecoder()
	var mappings []Mapping

	lines := strings.Split(sm.Mappings, ";")
	genLine := 0

	for _, line := range lines {
		if line == "" {
			genLine++
			continue
		}

		fields := strings.Split(line, ",")
		genCol := 0

		for _, field := range fields {
			if field == "" {
				continue
			}

			decoded, consumed := decoder.Decode(field)
			if consumed == 0 {
				continue
			}
			genCol += decoded

			// Try to decode more fields (source, sourceLine, sourceCol, nameIndex)
			remaining := field[consumed:]
			if remaining == "" {
				continue
			}

			d2, c2 := decoder.Decode(remaining)
			remaining = remaining[c2:]
			if remaining == "" {
				continue
			}
			srcIdx := d2

			d3, c3 := decoder.Decode(remaining)
			remaining = remaining[c3:]
			if remaining == "" {
				continue
			}
			srcLine := d3

			d4, c4 := decoder.Decode(remaining)
			remaining = remaining[c4:]

			m := Mapping{
				GenLine:   genLine,
				GenColumn: genCol,
				SrcIndex:  srcIdx,
				SrcLine:   srcLine,
				SrcColumn: d4,
			}

			if sm.Sources != nil && srcIdx < len(sm.Sources) {
				m.SourceFile = sm.Sources[srcIdx]
			}

			mappings = append(mappings, m)
		}

		genLine++
	}

	return mappings
}

// Mapping represents a decoded source map mapping
type Mapping struct {
	GenLine    int
	GenColumn  int
	SrcIndex   int
	SrcLine    int
	SrcColumn  int
	SourceFile string
	Name       string
}

// ExtractContentByLine extracts source content for specific lines
func (sm *SourceMap) ExtractContentByLine(sourceFile string, startLine, endLine int) string {
	for i, src := range sm.Sources {
		if src == sourceFile && sm.SourcesContent != nil && i < len(sm.SourcesContent) {
			lines := strings.Split(sm.SourcesContent[i], "\n")
			if startLine < 1 {
				startLine = 1
			}
			if endLine > len(lines) {
				endLine = len(lines)
			}
			if startLine > len(lines) {
				return ""
			}
			return strings.Join(lines[startLine-1:endLine], "\n")
		}
	}
	return ""
}

func truncateContent(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ParseInt parses a string to int, returning 0 on error
func ParseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
