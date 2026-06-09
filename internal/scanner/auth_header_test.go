package scanner

import "testing"

func TestDetectAuthHeaders_Bearer(t *testing.T) {
	findings := DetectAuthHeaders(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`, "test.txt", 1)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for Bearer token")
	}
}

func TestDetectAuthHeaders_APIKey(t *testing.T) {
	findings := DetectAuthHeaders(`X-API-Key: sk-abcdef1234567890abcdef12`, "test.txt", 1)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for API key")
	}
}

func TestDetectAuthHeaders_NoMatch(t *testing.T) {
	findings := DetectAuthHeaders(`const x = 42;`, "test.txt", 1)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDetectAuthHeaders_BasicAuth(t *testing.T) {
	findings := DetectAuthHeaders(`Authorization: Basic dXNlcjpwYXNzd29yZA==`, "test.txt", 1)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for Basic auth")
	}
}
