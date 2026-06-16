package discovery

import (
	"net/http"
	"testing"
	"time"
)

func TestEnumerateSubdomains(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}
	subs, err := EnumerateSubdomains("example.com", client, false)
	if err != nil {
		t.Fatalf("enumerate subdomains: %v", err)
	}

	t.Logf("Found %d subdomains for example.com", len(subs))
	for _, s := range subs {
		t.Logf("  %s (%s)", s.Subdomain, s.Source)
	}

	// example.com should have at least the base domain
	if len(subs) == 0 {
		t.Error("expected at least 1 subdomain (example.com itself)")
	}
}

func TestIsTextMime(t *testing.T) {
	tests := []struct {
		mime string
		want bool
	}{
		{"text/html", true},
		{"application/json", true},
		{"image/png", false},
		{"application/pdf", false},
		{"TEXT/HTML", true},
	}
	for _, tt := range tests {
		got := isTextMime(tt.mime)
		if got != tt.want {
			t.Errorf("isTextMime(%q) = %v, want %v", tt.mime, got, tt.want)
		}
	}
}

func TestCheckLiveHosts(t *testing.T) {
	client := &http.Client{}
	results := CheckLiveHosts([]string{"example.com"}, client, 5*time.Second)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Alive {
		t.Error("expected example.com to be alive")
	}
	t.Logf("example.com: alive=%v status=%d", results[0].Alive, results[0].StatusCode)
}
