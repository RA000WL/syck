package scanner

import "testing"

func TestExtractURLSecrets(t *testing.T) {
	line := `githubWebhook:"https://api.github.com/hooks?access_token=ghp_FAKEGitHubToken1234567890abcdefABC"`
	findings := ExtractURLSecrets(line, "test.js", 1)
	if len(findings) == 0 {
		t.Fatal("expected findings from URL access_token")
	}
	found := false
	for _, f := range findings {
		if f.RuleName == "url_access_token" {
			found = true
		}
	}
	if !found {
		t.Error("expected url_access_token finding")
	}
}

func TestExtractURLSecretsNoToken(t *testing.T) {
	line := `var url = "https://example.com/page"`
	findings := ExtractURLSecrets(line, "test.js", 1)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
