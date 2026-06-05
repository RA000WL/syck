package endpoints

import (
	"testing"
)

func TestExtractAPIRoutes(t *testing.T) {
	content := `fetch("/api/v1/users", { method: "GET" })`
	endpoints := ExtractEndpoints("test.js", content)
	if len(endpoints) == 0 {
		t.Fatal("expected at least 1 endpoint")
	}
	found := false
	for _, ep := range endpoints {
		if ep.Endpoint == "/api/v1/users" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /api/v1/users, got %v", endpoints)
	}
}

func TestExtractGraphQL(t *testing.T) {
	content := `"https://example.com/graphql"`
	endpoints := ExtractEndpoints("test.js", content)
	found := false
	for _, ep := range endpoints {
		if ep.Endpoint == "https://example.com/graphql" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected graphql endpoint, got %v", endpoints)
	}
}

func TestExtractWebSocket(t *testing.T) {
	content := `const ws = new WebSocket("wss://realtime.example.com/socket")`
	endpoints := ExtractEndpoints("test.js", content)
	found := false
	for _, ep := range endpoints {
		if ep.Endpoint == "wss://realtime.example.com/socket" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected wss endpoint, got %v", endpoints)
	}
}

func TestExtractAuthRoutes(t *testing.T) {
	content := `"POST /auth/login"`
	endpoints := ExtractEndpoints("test.js", content)
	found := false
	for _, ep := range endpoints {
		if ep.Endpoint == "/auth/login" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /auth/login, got %v", endpoints)
	}
}

func TestExtractSkipsStaticAssets(t *testing.T) {
	content := `"/api/image.png" "/api/users"`
	endpoints := ExtractEndpoints("test.js", content)
	if len(endpoints) == 0 {
		t.Error("expected at least 1 non-static endpoint")
	}
	for _, ep := range endpoints {
		if ep.Endpoint == "/api/image.png" {
			t.Error("should skip .png files")
		}
	}
}

func TestExtractDeduplicates(t *testing.T) {
	content := `"/api/v1/users" "/api/v1/users"`
	endpoints := ExtractEndpoints("test.js", content)
	// Exact duplicate from same pattern should be deduped by seen set
	// Different patterns may still match overlapping content (INFO-level noise is acceptable)
	if len(endpoints) == 0 {
		t.Errorf("expected at least 1 deduplicated endpoint, got 0")
	}
	seen := make(map[string]int)
	for _, ep := range endpoints {
		seen[ep.Endpoint]++
	}
	for ep, count := range seen {
		if count > 1 {
			t.Errorf("endpoint %q appears %d times (expected max 1)", ep, count)
		}
	}
}

func TestExtractSkipsShort(t *testing.T) {
	content := `"/ab"`
	endpoints := ExtractEndpoints("test.js", content)
	if len(endpoints) != 0 {
		t.Errorf("expected 0 for short endpoint, got %d", len(endpoints))
	}
}

func TestExtractFetchAxios(t *testing.T) {
	content := `axios.get("https://api.example.com/data")`
	endpoints := ExtractEndpoints("test.js", content)
	found := false
	for _, ep := range endpoints {
		if ep.Endpoint == "https://api.example.com/data" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected axios URL, got %v", endpoints)
	}
}
