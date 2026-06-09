package endpoints

import (
	"strings"
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

func TestExtractRouterPaths(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"path_kv", `{ path: "/admin/users", component: X }`, "/admin/users"},
		{"RouteComponent", `<Route path="/billing" />`, "/billing"},
		{"RouterPush", `router.push("/profile")`, "/profile"},
		{"Navigate", `navigate("/settings")`, "/settings"},
		{"LinkTo", `<Link to="/dashboard">`, "/dashboard"},
		{"AnchorHref", `<a href="/profile">u</a>`, "/profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eps := ExtractEndpoints("test.js", tc.line)
			found := false
			for _, ep := range eps {
				if ep.Endpoint == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q in %q, got %v", tc.want, tc.line, eps)
			}
		})
	}
}

func TestExtractGraphQLVariants(t *testing.T) {
	cases := []string{
		`"https://example.com/graphql"`,
		`"https://example.com/api/graphql"`,
		`"https://example.com/graphql/v1"`,
		`"https://example.com/query"`,
		`"https://example.com/gql"`,
		`graphqlClient: "/api/graphql"`,
	}
	for _, content := range cases {
		eps := ExtractEndpoints("test.js", content)
		if len(eps) == 0 {
			t.Errorf("expected endpoint in %q, got none", content)
		}
	}
}

func TestExtractOpenAPI(t *testing.T) {
	cases := []string{
		`"https://example.com/openapi.json"`,
		`"https://example.com/swagger.json"`,
		`"https://example.com/v3/api-docs"`,
	}
	for _, content := range cases {
		eps := ExtractEndpoints("test.js", content)
		if len(eps) == 0 {
			t.Errorf("expected OpenAPI endpoint in %q, got none", content)
		}
	}
}

func TestExtractComputedProperties(t *testing.T) {
	content := "const url = baseURL + '/api/v1/users/' + userId;"
	eps := ExtractEndpoints("test.js", content)
	found := false
	for _, ep := range eps {
		if strings.Contains(ep.Endpoint, "/api/v1/users") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /api/v1/users in endpoints, got %+v", eps)
	}
}

func TestExtractTemplateLiterals(t *testing.T) {
	content := "fetch(`https://api.example.com/users/${userId}/profile`)"
	eps := ExtractEndpoints("test.js", content)
	if len(eps) < 1 {
		t.Fatal("expected at least 1 endpoint from template literal")
	}
}
