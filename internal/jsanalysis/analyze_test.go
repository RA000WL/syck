package jsanalysis

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func secretHasType(secrets []SecretFinding, typ string) bool {
	for _, s := range secrets {
		if s.Type == typ {
			return true
		}
	}
	return false
}

func TestExtractEnvVars_ProcessEnv(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "single process.env access",
			content:  `const key = process.env.API_KEY;`,
			expected: []string{"API_KEY"},
		},
		{
			name:     "multiple process.env on one line",
			content:  `const a = process.env.FOO + process.env.BAR;`,
			expected: []string{"FOO", "BAR"},
		},
		{
			name:     "process.env with underscore prefix",
			content:  `const x = process.env._PRIVATE;`,
			expected: []string{"_PRIVATE"},
		},
		{
			name:     "process.env bracket single quotes",
			content:  `const x = process.env['MY_SECRET'];`,
			expected: []string{"MY_SECRET"},
		},
		{
			name:     "process.env bracket double quotes",
			content:  `const x = process.env["MY_SECRET"];`,
			expected: []string{"MY_SECRET"},
		},
		{
			name:     "process.env bracket with numeric",
			content:  `const x = process.env['DB_HOST_3'];`,
			expected: []string{"DB_HOST_3"},
		},
		{
			name:     "duplicate env vars deduplicated",
			content:  "const a = process.env.KEY;\nconst b = process.env.KEY;",
			expected: []string{"KEY"},
		},
		{
			name:     "invalid env var (starts with digit) ignored",
			content:  `const x = process.env.123BAD;`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "test.js")
			if len(result.EnvVars) != len(tt.expected) {
				t.Errorf("got %v, want %v", result.EnvVars, tt.expected)
				return
			}
			for i, v := range result.EnvVars {
				if v != tt.expected[i] {
					t.Errorf("EnvVars[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestExtractEnvVars_ImportMetaEnv(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "import.meta.env access",
			content:  `const api = import.meta.env.VITE_API_URL;`,
			expected: []string{"IMPORT_META_VITE_API_URL"},
		},
		{
			name:     "multiple import.meta.env",
			content:  `const a = import.meta.env.MODE; const b = import.meta.env.PROD;`,
			expected: []string{"IMPORT_META_MODE", "IMPORT_META_PROD"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "test.ts")
			if len(result.EnvVars) != len(tt.expected) {
				t.Errorf("got %v, want %v", result.EnvVars, tt.expected)
				return
			}
			for i, v := range result.EnvVars {
				if v != tt.expected[i] {
					t.Errorf("EnvVars[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestExtractEnvVars_MixedPatterns(t *testing.T) {
	content := `
const a = process.env.API_KEY;
const b = process.env["AUTH_TOKEN"];
const c = import.meta.env.VITE_URL;
`
	result := AnalyzeJS(content, "test.js")
	if len(result.EnvVars) != 3 {
		t.Errorf("expected 3 env vars, got %d: %v", len(result.EnvVars), result.EnvVars)
	}
}

func TestDynamicImports(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name:     "dynamic import single quotes",
			content:  `const mod = import('./utils/helper');`,
			expected: []string{"./utils/helper"},
		},
		{
			name:     "dynamic import double quotes",
			content:  `const mod = import("./pages/Dashboard");`,
			expected: []string{"./pages/Dashboard"},
		},
		{
			name:     "dynamic import backtick",
			content:  "const mod = import(`./lazy/${name}`);",
			expected: []string{"./lazy/${name}"},
		},
		{
			name:     "require with path",
			content:  `const r = require('./lib/foo');`,
			expected: []string{"./lib/foo"},
		},
		{
			name:     "require with absolute-like path",
			content:  `const r = require('/utils/bar');`,
			expected: []string{"/utils/bar"},
		},
		{
			name:     "require bare module ignored",
			content:  `const r = require('react');`,
			expected: nil,
		},
		{
			name:     "require bare module ignored double quotes",
			content:  `const r = require("lodash");`,
			expected: nil,
		},
		{
			name:     "multiple dynamic imports",
			content:  `import('./a'); import("./b");`,
			expected: []string{"./a", "./b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "test.js")
			if len(result.Endpoints) != len(tt.expected) {
				t.Errorf("got Endpoints %v, want %v", result.Endpoints, tt.expected)
				return
			}
			for i, e := range result.Endpoints {
				if e != tt.expected[i] {
					t.Errorf("Endpoints[%d] = %q, want %q", i, e, tt.expected[i])
				}
			}
		})
	}
}

func TestWebpackChunks(t *testing.T) {
	tests := []struct {
		name    string
		content string
		chunk   string
	}{
		{
			name:    "webpackChunk with chunk import",
			content: `if (webpackChunk) { import('chunk.abc123.js'); }`,
			chunk:   "chunk.abc123.js",
		},
		{
			name:    "__webpack_require__ with chunk",
			content: `__webpack_require__ = import('chunk.vendor.js');`,
			chunk:   "chunk.vendor.js",
		},
		{
			name:    "webpack_modules with chunk",
			content: `webpack_modules.load = import('chunk.main.js');`,
			chunk:   "chunk.main.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "bundle.js")
			if !contains(result.Chunks, tt.chunk) {
				t.Errorf("expected %q in Chunks, got %v", tt.chunk, result.Chunks)
			}
		})
	}
}

func TestViteChunks(t *testing.T) {
	tests := []struct {
		name    string
		content string
		chunk   string
	}{
		{
			name:    "__vite_ssr_loadModule with chunk",
			content: `const a = __vite_ssr_loadModule; import('chunk.main.js');`,
			chunk:   "chunk.main.js",
		},
		{
			name:    "vite/client with chunk",
			content: `vite/client.config = import('chunk.app.js');`,
			chunk:   "chunk.app.js",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "app.js")
			if !contains(result.Chunks, tt.chunk) {
				t.Errorf("expected %q in Chunks, got %v", tt.chunk, result.Chunks)
			}
		})
	}
}

func TestChunkImportNotMatchedWithoutBundlerContext(t *testing.T) {
	content := `import('chunk.something.js');`
	result := AnalyzeJS(content, "app.js")
	if len(result.Chunks) > 0 {
		t.Errorf("expected no chunks without bundler context, got %v", result.Chunks)
	}
}

func TestCommentLeakedURLs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		urls    []string
	}{
		{
			name:    "line comment with URL right after",
			content: `// https://internal.example.com/admin`,
			urls:    []string{"https://internal.example.com/admin"},
		},
		{
			name:    "http URL in comment",
			content: `// http://10.0.0.1:8080/api`,
			urls:    []string{"http://10.0.0.1:8080/api"},
		},
		{
			name:    "multiple comments with URLs",
			content: "// https://foo.com\n// https://bar.com",
			urls:    []string{"https://foo.com", "https://bar.com"},
		},
		{
			name:    "comment without URL",
			content: `// TODO: fix this later`,
			urls:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "test.js")
			for _, u := range tt.urls {
				if !contains(result.LeakedComments, u) {
					t.Errorf("expected %q in LeakedComments, got %v", u, result.LeakedComments)
				}
			}
			if len(tt.urls) == 0 && len(result.LeakedComments) != 0 {
				t.Errorf("expected no LeakedComments, got %v", result.LeakedComments)
			}
		})
	}
}

func TestTodoSecrets(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		expectFind bool
	}{
		{
			name:       "TODO with key",
			content:    `// TODO: rotate API key after deploy`,
			expectFind: true,
		},
		{
			name:       "FIXME with token",
			content:    `// FIXME: hardcoded token needs removal`,
			expectFind: true,
		},
		{
			name:       "HACK with password",
			content:    `// HACK: temporary password for testing`,
			expectFind: true,
		},
		{
			name:       "XXX with secret",
			content:    `/* XXX: secret in config */`,
			expectFind: true,
		},
		{
			name:       "TODO without sensitive word",
			content:    `// TODO: refactor this function`,
			expectFind: false,
		},
		{
			name:       "TEMP with key",
			content:    `// TEMP: backup key stored here`,
			expectFind: true,
		},
		{
			name:       "FIXME semicolon separator",
			content:    `// FIXME; token is expired`,
			expectFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "test.js")
			found := false
			for _, s := range result.Secrets {
				if s.Type == "comment_leak" {
					found = true
				}
			}
			if found != tt.expectFind {
				t.Errorf("expected find=%v for %q, got %v (secrets: %v)", tt.expectFind, tt.name, found, result.Secrets)
			}
		})
	}
}

func TestTodoSecretValues(t *testing.T) {
	content := `// TODO: rotate API key after deploy`
	result := AnalyzeJS(content, "test.js")
	for _, s := range result.Secrets {
		if s.Type == "comment_leak" {
			if s.Value != "rotate API key after deploy" {
				t.Errorf("secret value = %q, want %q", s.Value, "rotate API key after deploy")
			}
			if s.Context != "TODO/FIXME comment" {
				t.Errorf("secret context = %q, want %q", s.Context, "TODO/FIXME comment")
			}
		}
	}
}

func TestBase64Secrets(t *testing.T) {
	// Encode a string that's 40+ chars and contains a sensitive word
	plaintext := "https://api.internal.corp/keys/activate"
	b64 := base64.StdEncoding.EncodeToString([]byte(plaintext))
	content := fmt.Sprintf("const encoded = '%s';", b64)
	result := AnalyzeJS(content, "test.js")
	if !secretHasType(result.Secrets, "base64") {
		t.Error("expected base64 secret to be found")
		return
	}
	for _, s := range result.Secrets {
		if s.Type == "base64" {
			if !strings.Contains(s.Context, plaintext) {
				t.Errorf("expected decoded context to contain %q, got %q", plaintext, s.Context)
			}
			if s.Value != b64 {
				t.Errorf("expected Value to be the base64 string, got %q", s.Value)
			}
		}
	}
}

func TestBase64NoMatchForShortStrings(t *testing.T) {
	content := `const x = 'abc';`
	result := AnalyzeJS(content, "test.js")
	for _, s := range result.Secrets {
		if s.Type == "base64" {
			t.Error("short string should not be detected as base64 secret")
		}
	}
}

func TestBase64NonSecret(t *testing.T) {
	// Encode text that doesn't contain http/key/token/secret
	plaintext := "the quick brown fox jumps over the lazy dog today"
	b64 := base64.StdEncoding.EncodeToString([]byte(plaintext))
	content := fmt.Sprintf("const x = '%s';", b64)
	result := AnalyzeJS(content, "test.js")
	for _, s := range result.Secrets {
		if s.Type == "base64" {
			t.Errorf("non-secret base64 should not be flagged, decoded to %q", s.Context)
		}
	}
}

func TestBase64RawEncoding(t *testing.T) {
	// Test with raw (unpadded) base64
	plaintext := "https://raw.base64.test/endpoint/here"
	b64 := base64.RawStdEncoding.EncodeToString([]byte(plaintext))
	content := fmt.Sprintf("const x = '%s';", b64)
	result := AnalyzeJS(content, "test.js")
	if !secretHasType(result.Secrets, "base64") {
		t.Error("expected raw base64 secret to be found")
	}
}

func TestConfigURLs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		url     string
	}{
		{
			name:    "baseURL",
			content: `const baseURL = "https://api.example.com/v2";`,
			url:     "https://api.example.com/v2",
		},
		{
			name:    "api_url",
			content: `const api_url = 'https://staging.api.internal:3000';`,
			url:     "https://staging.api.internal:3000",
		},
		{
			name:    "endpoint",
			content: `endpoint: "https://graphql.example.com"`,
			url:     "https://graphql.example.com",
		},
		{
			name:    "host",
			content: `host: "db.internal.corp:5432"`,
			url:     "db.internal.corp:5432",
		},
		{
			name:    "server config",
			content: `server: "https://admin.staging.example.com"`,
			url:     "https://admin.staging.example.com",
		},
		{
			name:    "apiURL",
			content: `apiURL: "https://backup.api.com"`,
			url:     "https://backup.api.com",
		},
		{
			name:    "origin",
			content: `origin: "https://cdn.example.com"`,
			url:     "https://cdn.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "config.js")
			if !contains(result.Endpoints, tt.url) {
				t.Errorf("expected %q in Endpoints, got %v", tt.url, result.Endpoints)
			}
		})
	}
}

func TestConfigSecrets(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		expectFind bool
		value      string
	}{
		{
			name:       "apiKey with real value",
			content:    `apiKey: "sk-proj-abc123xyz789"`,
			expectFind: true,
			value:      "sk-proj-abc123xyz789",
		},
		{
			name:       "token with real value",
			content:    `token = "ghp_xxxxxxxxxxxxxxxxxxxx"`,
			expectFind: true,
			value:      "ghp_xxxxxxxxxxxxxxxxxxxx",
		},
		{
			name:       "password placeholder xxx",
			content:    `password: "xxx"`,
			expectFind: false,
		},
		{
			name:       "secret placeholder your_key_here",
			content:    `secret: "your_key_here"`,
			expectFind: false,
		},
		{
			name:       "auth placeholder CHANGE_ME",
			content:    `auth: "CHANGE_ME"`,
			expectFind: false,
		},
		{
			name:       "short value ignored",
			content:    `apiKey: "abc"`,
			expectFind: false,
		},
		{
			name:       "api_key with long value",
			content:    `api_key = "real-key-1234567890abc"`,
			expectFind: true,
			value:      "real-key-1234567890abc",
		},
		{
			name:       "secret with real value",
			content:    `secret: "mydatabasepass123"`,
			expectFind: true,
			value:      "mydatabasepass123",
		},
		{
			name:       "password with real value",
			content:    `password: "admin123456"`,
			expectFind: true,
			value:      "admin123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "config.js")
			found := false
			for _, s := range result.Secrets {
				if s.Type == "config_secret" {
					found = true
					if tt.value != "" && s.Value != tt.value {
						t.Errorf("secret value = %q, want %q", s.Value, tt.value)
					}
				}
			}
			if found != tt.expectFind {
				t.Errorf("expected find=%v, got %v", tt.expectFind, found)
			}
		})
	}
}

func TestInternalServiceURLs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		url     string
	}{
		{
			name:    "internal keyword",
			content: `internal: "api-internal.corp"`,
			url:     "api-internal.corp",
		},
		{
			name:    "staging keyword",
			content: `staging: "staging-db.internal:5432"`,
			url:     "staging-db.internal:5432",
		},
		{
			name:    "dev keyword",
			content: `dev: "dev-cache.local"`,
			url:     "dev-cache.local",
		},
		{
			name:    "sandbox keyword",
			content: `sandbox: "sandbox-service"`,
			url:     "sandbox-service",
		},
		{
			name:    "test keyword",
			content: `test: "test-auth.internal"`,
			url:     "test-auth.internal",
		},
		{
			name:    "private keyword",
			content: `private: "private-registry.corp"`,
			url:     "private-registry.corp",
		},
		{
			name:    "corp keyword",
			content: `corp: "corp-proxy.internal"`,
			url:     "corp-proxy.internal",
		},
		{
			name:    "intranet keyword",
			content: `intranet: "intranet-portal.corp"`,
			url:     "intranet-portal.corp",
		},
		{
			name:    "staging with equals",
			content: `staging = "staging-api.internal"`,
			url:     "staging-api.internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "config.js")
			if !contains(result.InternalURLs, tt.url) {
				t.Errorf("expected %q in InternalURLs, got %v", tt.url, result.InternalURLs)
			}
		})
	}
}

func TestLocalhostURLs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		url     string
	}{
		{
			name:    "localhost:3000",
			content: `const API = "http://localhost:3000/api";`,
			url:     "localhost:3000",
		},
		{
			name:    "127.0.0.1:5432",
			content: `DB_HOST: "127.0.0.1:5432"`,
			url:     "127.0.0.1:5432",
		},
		{
			name:    "0.0.0.0:8080",
			content: `listen: "0.0.0.0:8080"`,
			url:     "0.0.0.0:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "server.js")
			if !contains(result.InternalURLs, tt.url) {
				t.Errorf("expected %q in InternalURLs, got %v", tt.url, result.InternalURLs)
			}
		})
	}
}

func TestSensitiveFileReferences(t *testing.T) {
	tests := []struct {
		name    string
		content string
		file    string
	}{
		{
			name:    ".env file",
			content: `require('./.env');`,
			file:    "./.env",
		},
		{
			name:    ".pem file",
			content: `const key = '/etc/ssl/private/server.pem';`,
			file:    "/etc/ssl/private/server.pem",
		},
		{
			name:    "credentials.json",
			content: `const creds = require('./credentials.json');`,
			file:    "./credentials.json",
		},
		{
			name:    "secrets.json",
			content: `load('./config/secrets.json');`,
			file:    "./config/secrets.json",
		},
		{
			name:    "service-account",
			content: `const sa = 'service-account.json';`,
			file:    "service-account.json",
		},
		{
			name:    ".key file",
			content: `const k = '/app/keys/private.key';`,
			file:    "/app/keys/private.key",
		},
		{
			name:    ".cert file",
			content: `cert: '/etc/ssl/cert.pem'`,
			file:    "/etc/ssl/cert.pem",
		},
		{
			name:    ".p12 file",
			content: `const cert = 'keystore.p12';`,
			file:    "keystore.p12",
		},
		{
			name:    ".pfx file",
			content: `const p = 'server.pfx';`,
			file:    "server.pfx",
		},
		{
			name:    ".jks file",
			content: `const j = 'keystore.jks';`,
			file:    "keystore.jks",
		},
		{
			name:    "service_account variant",
			content: `const sa = 'my-service-account.json';`,
			file:    "my-service-account.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "app.js")
			if !contains(result.SensitiveFiles, tt.file) {
				t.Errorf("expected %q in SensitiveFiles, got %v", tt.file, result.SensitiveFiles)
			}
		})
	}
}

func TestDebugArtifacts(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "debug URL",
			content: `const debugUrl = '/debug/vars';`,
		},
		{
			name:    "trace endpoint",
			content: `const trace = "/trace/request";`,
		},
		{
			name:    "devtools reference",
			content: `const url = "/devtools/inspect";`,
		},
		{
			name:    "console reference",
			content: `const path = '/console/logs';`,
		},
		{
			name:    "profile reference",
			content: `const p = "profile/stats";`,
		},
		{
			name:    "inspect reference",
			content: `load('/inspect/heap');`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "app.js")
			if len(result.DebugArtifacts) == 0 {
				t.Errorf("expected debug artifact for %q", tt.name)
			}
		})
	}
}

func TestDebugArtifactsContent(t *testing.T) {
	content := `const debugUrl = '/debug/vars';`
	result := AnalyzeJS(content, "app.js")
	if !contains(result.DebugArtifacts, "/debug/vars") {
		t.Errorf("expected /debug/vars in DebugArtifacts, got %v", result.DebugArtifacts)
	}
}

func TestSourceMaps(t *testing.T) {
	tests := []struct {
		name    string
		content string
		mapFile string
	}{
		{
			name:    "sourceMappingURL comment",
			content: `//# sourceMappingURL=app.js.map`,
			mapFile: "app.js.map",
		},
		{
			name:    "sourceURL assignment",
			content: `sourceURL: "bundle.js.map"`,
			mapFile: "bundle.js.map",
		},
		{
			name:    "minified with sourceMappingURL",
			content: `//# sourceMappingURL=vendor.min.js.map`,
			mapFile: "vendor.min.js.map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "app.min.js")
			if !contains(result.SourceMaps, tt.mapFile) {
				t.Errorf("expected %q in SourceMaps, got %v", tt.mapFile, result.SourceMaps)
			}
		})
	}
}

func TestAPIVersioning(t *testing.T) {
	tests := []struct {
		name    string
		content string
		path    string
	}{
		{
			name:    "v1 path",
			content: `const url = "/api/v1/users";`,
			path:    "/api/v1/users",
		},
		{
			name:    "v2 endpoint",
			content: `endpoint: "https://api.example.com/v2/data"`,
			path:    "https://api.example.com/v2/data",
		},
		{
			name:    "version/3",
			content: `path: "/api/version/3/compat"`,
			path:    "/api/version/3/compat",
		},
		{
			name:    "v10 path",
			content: `const url = "/api/v10/admin";`,
			path:    "/api/v10/admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "api.js")
			if !contains(result.Endpoints, tt.path) {
				t.Errorf("expected %q in Endpoints, got %v", tt.path, result.Endpoints)
			}
		})
	}
}

func TestHiddenRoutes(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		expectFind bool
		path       string
	}{
		{
			name:       "route path",
			content:    `route: "/admin/dashboard"`,
			expectFind: true,
			path:       "/admin/dashboard",
		},
		{
			name:       "redirect path",
			content:    `redirect: "/internal/legacy"`,
			expectFind: true,
			path:       "/internal/legacy",
		},
		{
			name:       "forward path",
			content:    `forward: "/proxy/api"`,
			expectFind: true,
			path:       "/proxy/api",
		},
		{
			name:       "comment path ignored",
			content:    `// route: "//not-a-path"`,
			expectFind: false,
		},
		{
			name:       "no leading slash ignored",
			content:    `path: "relative/path"`,
			expectFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "routes.js")
			found := contains(result.Endpoints, tt.path)
			if found != tt.expectFind {
				t.Errorf("expected find=%v for %q, got %v (Endpoints: %v)", tt.expectFind, tt.path, found, result.Endpoints)
			}
		})
	}
}

func TestAnalyzeJS_EmptyContent(t *testing.T) {
	result := AnalyzeJS("", "empty.js")
	if len(result.EnvVars) != 0 || len(result.Endpoints) != 0 || len(result.Secrets) != 0 {
		t.Errorf("expected empty result, got %+v", result)
	}
	if len(result.InternalURLs) != 0 || len(result.DebugArtifacts) != 0 || len(result.SourceMaps) != 0 {
		t.Errorf("expected empty result fields, got %+v", result)
	}
	if len(result.SensitiveFiles) != 0 || len(result.Chunks) != 0 || len(result.LeakedComments) != 0 {
		t.Errorf("expected empty result fields, got %+v", result)
	}
}

func TestAnalyzeJS_ComprehensiveJS(t *testing.T) {
	content := `
// https://internal.example.com/admin
const API_KEY = process.env.API_KEY;
const TOKEN = process.env["AUTH_TOKEN"];
const BASE = import.meta.env.VITE_API_BASE;

const config = {
  baseURL: "https://api.prod.example.com/v2",
  apiKey: "sk-1234567890abcdef1234",
  secret: "CHANGE_ME"
};

internal: "internal-service:8080";

const localhost = "http://localhost:4000/debug";

const module = import('./components/Dashboard');
const cert = '/etc/ssl/certs/app.pem';

//# sourceMappingURL=app.js.map

// TODO: rotate password for database
`
	result := AnalyzeJS(content, "app.js")

	if len(result.EnvVars) < 3 {
		t.Errorf("expected at least 3 env vars, got %v", result.EnvVars)
	}
	if !contains(result.Endpoints, "https://api.prod.example.com/v2") {
		t.Error("expected prod URL in endpoints")
	}
	if !contains(result.Endpoints, "./components/Dashboard") {
		t.Error("expected dynamic import in endpoints")
	}
	if len(result.Secrets) == 0 {
		t.Error("expected secrets to be found")
	}
	if !contains(result.InternalURLs, "localhost:4000") {
		t.Error("expected localhost in InternalURLs")
	}
	if !contains(result.SensitiveFiles, "/etc/ssl/certs/app.pem") {
		t.Error("expected pem file in SensitiveFiles")
	}
	if !contains(result.SourceMaps, "app.js.map") {
		t.Error("expected source map")
	}
}

func TestAnalyzeJS_FilePathParameter(t *testing.T) {
	content := `const x = process.env.TEST;`
	result := AnalyzeJS(content, "some/path/file.js")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{
			name:     "append to empty",
			slice:    nil,
			item:     "new",
			expected: []string{"new"},
		},
		{
			name:     "append unique",
			slice:    []string{"a", "b"},
			item:     "c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "skip duplicate",
			slice:    []string{"a", "b"},
			item:     "a",
			expected: []string{"a", "b"},
		},
		{
			name:     "trim whitespace",
			slice:    []string{"a"},
			item:     "  b  ",
			expected: []string{"a", "b"},
		},
		{
			name:     "skip empty after trim",
			slice:    []string{"a"},
			item:     "   ",
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUnique(tt.slice, tt.item)
			if len(result) != len(tt.expected) {
				t.Errorf("got %v, want %v", result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("result[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestTryDecodeBase64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid base64",
			input:    "SGVsbG8=",
			expected: "Hello",
		},
		{
			name:     "valid raw base64",
			input:    "SGVsbG8",
			expected: "Hello",
		},
		{
			name:     "invalid base64",
			input:    "not-valid-base64!!!",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "non-utf8 result",
			input:    "\xff\xfe",
			expected: "",
		},
		{
			name:     "url safe base64 decoded",
			input:    "aHR0cHM6Ly9leGFtcGxlLmNvbQ==",
			expected: "https://example.com",
		},
		{
			name:     "longer base64",
			input:    "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n",
			expected: "This is a test string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tryDecodeBase64(tt.input)
			if result != tt.expected {
				t.Errorf("tryDecodeBase64(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSecretFinding_LineNumbers(t *testing.T) {
	content := `// TODO: fix the token issue
const x = 1;
// TODO: rotate key`
	result := AnalyzeJS(content, "test.js")
	for _, s := range result.Secrets {
		if s.Line <= 0 {
			t.Errorf("expected positive line number, got %d", s.Line)
		}
	}
	if len(result.Secrets) >= 2 {
		if result.Secrets[0].Line != 1 {
			t.Errorf("first secret line = %d, want 1", result.Secrets[0].Line)
		}
		if result.Secrets[1].Line != 3 {
			t.Errorf("second secret line = %d, want 3", result.Secrets[1].Line)
		}
	}
}

func TestAnalyzeJS_Deduplication(t *testing.T) {
	content := `
const a = process.env.KEY;
const b = process.env.KEY;
const c = process.env.KEY;
`
	result := AnalyzeJS(content, "test.js")
	count := 0
	for _, v := range result.EnvVars {
		if v == "KEY" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected KEY to appear once after dedup, appeared %d times", count)
	}
}

func TestAnalyzeJS_DedupEndpoints(t *testing.T) {
	content := `
import('./foo');
import('./foo');
`
	result := AnalyzeJS(content, "test.js")
	count := 0
	for _, v := range result.Endpoints {
		if v == "./foo" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected ./foo endpoint once, appeared %d times", count)
	}
}

func TestAnalyzeJS_LargeInput(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&builder, "const v%d = process.env.VAR_%d;\n", i, i)
	}
	result := AnalyzeJS(builder.String(), "big.js")
	if len(result.EnvVars) != 1000 {
		t.Errorf("expected 1000 unique env vars, got %d", len(result.EnvVars))
	}
}

func TestAnalyzeJS_NoFalsePositives(t *testing.T) {
	content := `
const x = 42;
const y = "hello";
const z = [1, 2, 3];
function foo() { return true; }
`
	result := AnalyzeJS(content, "clean.js")
	if len(result.Secrets) != 0 {
		t.Errorf("expected no secrets in clean code, got %v", result.Secrets)
	}
	if len(result.Endpoints) != 0 {
		t.Errorf("expected no endpoints in clean code, got %v", result.Endpoints)
	}
	if len(result.EnvVars) != 0 {
		t.Errorf("expected no env vars in clean code, got %v", result.EnvVars)
	}
	if len(result.InternalURLs) != 0 {
		t.Errorf("expected no internal URLs in clean code, got %v", result.InternalURLs)
	}
	if len(result.DebugArtifacts) != 0 {
		t.Errorf("expected no debug artifacts in clean code, got %v", result.DebugArtifacts)
	}
	if len(result.SourceMaps) != 0 {
		t.Errorf("expected no source maps in clean code, got %v", result.SourceMaps)
	}
	if len(result.SensitiveFiles) != 0 {
		t.Errorf("expected no sensitive files in clean code, got %v", result.SensitiveFiles)
	}
	if len(result.Chunks) != 0 {
		t.Errorf("expected no chunks in clean code, got %v", result.Chunks)
	}
	if len(result.LeakedComments) != 0 {
		t.Errorf("expected no leaked comments in clean code, got %v", result.LeakedComments)
	}
}

func TestBlockComments(t *testing.T) {
	content := `
/* 
  This block comment has no URLs
  but mentions some things
*/
const x = 1;
`
	result := AnalyzeJS(content, "test.js")
	if len(result.LeakedComments) != 0 {
		t.Errorf("block comment should not leak, got %v", result.LeakedComments)
	}
}

func TestConfigKeyRE_Insensitive(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		expectFind bool
	}{
		{
			name:       "apikey lowercase",
			content:    `apikey: "longvalue123456"`,
			expectFind: true,
		},
		{
			name:       "Api_Key mixed case",
			content:    `Api_Key: "longvalue123456"`,
			expectFind: true,
		},
		{
			name:       "SECRET lowercase",
			content:    `secret: "longvalue123456"`,
			expectFind: true,
		},
		{
			name:       "TOKEN lowercase",
			content:    `token: "longvalue123456"`,
			expectFind: true,
		},
		{
			name:       "AUTH mixed case",
			content:    `auth: "longvalue123456"`,
			expectFind: true,
		},
		{
			name:       "PASSWORD lowercase",
			content:    `password: "longvalue123456"`,
			expectFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AnalyzeJS(tt.content, "config.js")
			found := false
			for _, s := range result.Secrets {
				if s.Type == "config_secret" {
					found = true
				}
			}
			if found != tt.expectFind {
				t.Errorf("expected find=%v, got %v", tt.expectFind, found)
			}
		})
	}
}

func TestMultilineAnalysis(t *testing.T) {
	content := `const API = process.env.API_KEY;
const BASE = import.meta.env.VITE_URL;
const mod = import('./lazy/page');
const cert = '/etc/ssl/cert.pem';
`
	result := AnalyzeJS(content, "multi.js")
	if len(result.EnvVars) != 2 {
		t.Errorf("expected 2 env vars, got %d: %v", len(result.EnvVars), result.EnvVars)
	}
	if len(result.Endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d: %v", len(result.Endpoints), result.Endpoints)
	}
	if len(result.SensitiveFiles) != 1 {
		t.Errorf("expected 1 sensitive file, got %d: %v", len(result.SensitiveFiles), result.SensitiveFiles)
	}
}

func TestSecretFindingTypes(t *testing.T) {
	content := `
const apiKey: "sk-real-1234567890abcdef";
// TODO: rotate password
`
	result := AnalyzeJS(content, "test.js")
	types := make(map[string]bool)
	for _, s := range result.Secrets {
		types[s.Type] = true
	}
	if !types["config_secret"] {
		t.Error("expected config_secret type")
	}
	if !types["comment_leak"] {
		t.Error("expected comment_leak type")
	}
}

func TestInternalServiceWithEquals(t *testing.T) {
	content := `staging = "staging-api.internal.com"`
	result := AnalyzeJS(content, "config.js")
	if !contains(result.InternalURLs, "staging-api.internal.com") {
		t.Errorf("expected staging URL in InternalURLs, got %v", result.InternalURLs)
	}
}

func TestMultipleInternalKeywords(t *testing.T) {
	content := `
internal: "api.internal.corp";
staging: "staging.db.corp";
`
	result := AnalyzeJS(content, "config.js")
	if !contains(result.InternalURLs, "api.internal.corp") {
		t.Error("expected api.internal.corp in InternalURLs")
	}
	if !contains(result.InternalURLs, "staging.db.corp") {
		t.Error("expected staging.db.corp in InternalURLs")
	}
}

func TestWhitespaceInContent(t *testing.T) {
	content := "const x = process.env.KEY;   \n  \t  \nconst y = process.env.VAL;\n"
	result := AnalyzeJS(content, "test.js")
	if len(result.EnvVars) != 2 {
		t.Errorf("expected 2 env vars, got %d: %v", len(result.EnvVars), result.EnvVars)
	}
}

func TestAnalysisResultStruct(t *testing.T) {
	r := &AnalysisResult{}
	if r.EnvVars != nil {
		t.Error("EnvVars should be nil by default")
	}
	if r.Endpoints != nil {
		t.Error("Endpoints should be nil by default")
	}
	if r.Secrets != nil {
		t.Error("Secrets should be nil by default")
	}
}

func TestSecretFindingStruct(t *testing.T) {
	s := SecretFinding{
		Value:   "test-value",
		Context: "test context",
		Type:    "config_secret",
		Line:    42,
	}
	if s.Value != "test-value" {
		t.Errorf("Value = %q", s.Value)
	}
	if s.Context != "test context" {
		t.Errorf("Context = %q", s.Context)
	}
	if s.Type != "config_secret" {
		t.Errorf("Type = %q", s.Type)
	}
	if s.Line != 42 {
		t.Errorf("Line = %d", s.Line)
	}
}

// TestLocalhostRE_Characterization pins the InternalURLs findings that
// localhostRE contributes, before any question of delegating it to
// internalurl.IsLoopback. Every other InternalURLs producer is internalServiceRE,
// which fires only on an internal/private/corp/... keyword followed by `:` or
// `=`, so the lines below are crafted to avoid it — and to avoid configURLRE's
// host/server/baseURL keyword list — leaving localhostRE as the sole producer.
func TestLocalhostRE_Characterization(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string // full InternalURLs slice, in order
	}{
		{
			// The three literals the regex knows, and the negative it must skip:
			// "example.com:8080" has the :port shape but is not a loopback host,
			// and is absent from the result.
			name: "three loopback literals plus a negative",
			line: `var db = "localhost:8080", cache = "127.0.0.1:3000", listen = "0.0.0.0:9000", cdn = "example.com:8080";`,
			want: []string{"localhost:8080", "127.0.0.1:3000", "0.0.0.0:9000"},
		},
		{
			name: "negative alone produces nothing",
			line: `var cdn = "example.com:8080";`,
			want: nil,
		},
		{
			name: "a non-loopback host:port produces nothing",
			line: `var api = "https://api.prod.example.com:443/v2";`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeJS(tt.line, "config.js").InternalURLs
			if !equalStrings(got, tt.want) {
				t.Errorf("InternalURLs = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLocalhostRE_UnanchoredSubspanExtraction pins the two properties of
// localhostRE that make delegating it to a host-parsing predicate impossible
// without changing the finding set. Both are deliberate here: this test exists
// to keep them visible, because they are the reason the regex stays.
//
//  1. UNANCHORED. The regex has no \b or (?<![\w.-]) guard, so it extracts a
//     SUFFIX of a longer host: "my-localhost:8080" is emitted as the finding
//     "localhost:8080". The emitted span is a substring of the typed host and is
//     not itself the host anybody wrote. internalurl.IsLoopback parses a host, so
//     it answers "false" for "my-localhost:8080" — the finding is LOST, and no
//     amount of predicate-fiddling recovers it, because the finding the current
//     code produces was never a host in the first place.
//
//  2. NARROW VOCABULARY, CASE-SENSITIVE, PORT REQUIRED. The regex knows exactly
//     three spellings (localhost, 127.0.0.1, 0.0.0.0), is case-sensitive, and
//     requires a :port. IsLoopback knows 127/8, ::1, the unspecified address and
//     "localhost" in any case, and requires no port. Delegating therefore moves
//     findings in both directions at once: 127.0.0.2, [::1] and LOCALHOST:8080
//     are ADDED, while the portless "localhost" stays out only because the
//     tokenizing wrapper drops it — which is the wrapper this change is meant to
//     avoid needing.
func TestLocalhostRE_UnanchoredSubspanExtraction(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		// Property 1: unanchored suffix.
		{
			name: "suffix of a hyphenated host is extracted",
			line: `var api = "http://my-localhost:8080/api";`,
			want: []string{"localhost:8080"},
		},
		{
			name: "suffix of a dotted host is extracted",
			line: `var api = "http://foo.localhost:8080/api";`,
			want: []string{"localhost:8080"},
		},
		{
			// Property 2: narrow, case-sensitive, port-required vocabulary.
			name: "uppercase spelling is not matched",
			line: `var api = "LOCALHOST:8080";`,
			want: nil,
		},
		{
			name: "a neighbouring host:port spelling is not matched",
			line: `var api = "http://localhostX:8080/api";`,
			want: nil,
		},
		{
			name: "127/8 beyond .0.1 is not matched",
			line: `var api = "http://127.0.0.2:8080/api";`,
			want: nil,
		},
		{
			name: "bracketed IPv6 loopback is not matched",
			line: `var api = "http://[::1]:8080/api";`,
			want: nil,
		},
		{
			name: "portless host is not matched",
			line: `var api = "http://127.0.0.1/api";`,
			want: nil,
		},
		{
			name: "bare localhost name is not matched",
			line: `if (window.location.hostname === "localhost") { fetch("/x") }`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeJS(tt.line, "config.js").InternalURLs
			if !equalStrings(got, tt.want) {
				t.Errorf("InternalURLs = %q, want %q", got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
