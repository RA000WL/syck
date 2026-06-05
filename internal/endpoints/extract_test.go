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
	for _, ep := range endpoints {
		if ep.Endpoint == "/api/image.png" {
			t.Error("should skip .png files")
		}
	}
}

func TestExtractDeduplicates(t *testing.T) {
	content := `"/api/v1/users" "/api/v1/users"`
	endpoints := ExtractEndpoints("test.js", content)
	if len(endpoints) != 1 {
		t.Errorf("expected 1 deduplicated endpoint, got %d", len(endpoints))
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
