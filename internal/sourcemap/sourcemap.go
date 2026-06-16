// Package sourcemap provides source map parsing for JavaScript files.
package sourcemap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SourceMap represents a parsed JavaScript source map
type SourceMap struct {
	Version  int      `json:"version"`
	File     string   `json:"file"`
	SourceRoot string  `json:"sourceRoot"`
	Sources  []string `json:"sources"`
	Names    []string `json:"names"`
	Mappings string   `json:"mappings"`
}

// SourceMapFile represents a file within a source map
type SourceMapFile struct {
	OriginalPath string
	SourceRoot   string
	FullPath     string
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

// ExtractFiles returns the list of original source files from the source map
func (sm *SourceMap) ExtractFiles() []SourceMapFile {
	var files []SourceMapFile
	seen := make(map[string]bool)

	for _, src := range sm.Sources {
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true

		fullPath := src
		if sm.SourceRoot != "" {
			fullPath = sm.SourceRoot + src
		}

		files = append(files, SourceMapFile{
			OriginalPath: src,
			SourceRoot:   sm.SourceRoot,
			FullPath:     fullPath,
		})
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

	for _, src := range sm.Sources {
		srcLower := strings.ToLower(src)

		// Check if filename suggests it might contain secrets
		for _, pattern := range secretPatterns {
			if strings.Contains(srcLower, pattern) {
				secrets = append(secrets, SourceMapSecret{
					SourceFile: src,
					Pattern:    pattern,
					Reason:     fmt.Sprintf("filename contains '%s'", pattern),
				})
				break
			}
		}

		// Check for config/env files
		configPatterns := []string{
			"config", "env", "settings", "constants",
			"secrets", "credentials", "auth",
		}
		for _, pattern := range configPatterns {
			if strings.Contains(srcLower, pattern) {
				secrets = append(secrets, SourceMapSecret{
					SourceFile: src,
					Pattern:    pattern,
					Reason:     fmt.Sprintf("filename suggests config/secrets file (%s)", pattern),
				})
				break
			}
		}
	}

	return secrets
}

// SourceMapSecret represents a potential secret found in source map
type SourceMapSecret struct {
	SourceFile string
	Pattern    string
	Reason     string
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
