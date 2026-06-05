package jsrecon

import (
	"strings"
	"testing"
)

func TestAnalyzeFetchDetectsEndpoint(t *testing.T) {
	content := `fetch("https://api.example.com/v1/users")`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results")
	}
	if results[0].Method != "GET" {
		t.Errorf("Method = %q, want GET (default)", results[0].Method)
	}
	if results[0].Endpoint != "https://api.example.com/v1/users" {
		t.Errorf("Endpoint = %q, want https://api.example.com/v1/users", results[0].Endpoint)
	}
}

func TestAnalyzeFetchWithMethod(t *testing.T) {
	content := `fetch("https://api.example.com/data", {method: "POST"})`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results")
	}
	if results[0].Method != "POST" {
		t.Errorf("Method = %q, want POST", results[0].Method)
	}
}

func TestAnalyzeFetchWithAuthHeader(t *testing.T) {
	content := `fetch("https://api.example.com/secret", {headers: {"Authorization": "Bearer abcdef123456"}})`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results")
	}
	auth := results[0].Headers["Authorization"]
	if auth != "Bearer abcdef123456" {
		t.Errorf("Authorization = %q, want Bearer abcdef123456", auth)
	}
	if len(results[0].APIKeys) != 1 || results[0].APIKeys[0] != "abcdef123456" {
		t.Errorf("APIKeys = %v, want [abcdef123456]", results[0].APIKeys)
	}
}

func TestAnalyzeNonJSReturnsEmpty(t *testing.T) {
	results := Analyze("just some plain text", "plain.txt")
	if len(results) != 0 {
		t.Errorf("plain text produced %d results, want 0", len(results))
	}
}

func TestAnalyzeAxiosDetectsEndpoint(t *testing.T) {
	content := `axios.get("https://api.example.com/v2/items")`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results for axios.get")
	}
	if results[0].Method != "GET" {
		t.Errorf("Method = %q, want GET", results[0].Method)
	}
}

func TestAnalyzeXHRDetectsEndpoint(t *testing.T) {
	content := `var xhr = new XMLHttpRequest(); xhr.open("POST", "https://api.example.com/upload"); xhr.setRequestHeader("X-API-Key", "sk_test_12345");`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results for XHR")
	}
	if results[0].Method != "POST" {
		t.Errorf("Method = %q, want POST", results[0].Method)
	}
}

func TestAnalyzeGraphQLEndpoint(t *testing.T) {
	content := `const client = new ApolloClient({ uri: "https://api.example.com/graphql" })`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results for GraphQL")
	}
	if !strings.HasSuffix(results[0].Endpoint, "/graphql") {
		t.Errorf("Endpoint = %q, want suffix /graphql", results[0].Endpoint)
	}
}

func TestAnalyzeAuthorizationHeaderBearer(t *testing.T) {
	content := `"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.x"`
	results := Analyze(content, "test.js")
	if len(results) == 0 {
		t.Fatal("Analyze returned no results for Authorization header")
	}
	if len(results[0].APIKeys) == 0 {
		t.Fatal("no API keys extracted")
	}
}
