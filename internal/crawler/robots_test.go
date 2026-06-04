package crawler

import (
	"testing"
)

func TestParseRobotsTxt(t *testing.T) {
	content := `User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/
Crawl-delay: 2

User-agent: Googlebot
Disallow: /no-google/
`

	rule := parseRobotsTxt(content)
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}

	if len(rule.entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rule.entries))
	}

	// First rule: Disallow /admin/
	if rule.entries[0].allow || rule.entries[0].prefix != "/admin/" {
		t.Errorf("entry[0]: expected Disallow /admin/, got allow=%v prefix=%s", rule.entries[0].allow, rule.entries[0].prefix)
	}

	// Second rule: Disallow /private/
	if rule.entries[1].allow || rule.entries[1].prefix != "/private/" {
		t.Errorf("entry[1]: expected Disallow /private/, got allow=%v prefix=%s", rule.entries[1].allow, rule.entries[1].prefix)
	}

	// Third rule: Allow /public/
	if !rule.entries[2].allow || rule.entries[2].prefix != "/public/" {
		t.Errorf("entry[2]: expected Allow /public/, got allow=%v prefix=%s", rule.entries[2].allow, rule.entries[2].prefix)
	}

	// Crawl delay
	if rule.crawlDelay.Seconds() != 2 {
		t.Errorf("expected crawl-delay 2s, got %v", rule.crawlDelay)
	}
}

func TestParseRobotsTxtEmpty(t *testing.T) {
	rule := parseRobotsTxt("")
	if rule != nil {
		t.Errorf("expected nil for empty robots.txt, got %+v", rule)
	}
}

func TestParseRobotsTxtComments(t *testing.T) {
	content := `# This is a comment
User-agent: *
# Another comment
Disallow: /secret/
`
	rule := parseRobotsTxt(content)
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	if len(rule.entries) != 1 || rule.entries[0].prefix != "/secret/" {
		t.Errorf("expected Disallow /secret/, got %+v", rule.entries)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/admin", "/admin"},
		{"admin", "/admin"},
		{"/", "/"},
		{"", "/"},
	}
	for _, tt := range tests {
		got := normalizePath(tt.in)
		if got != tt.want {
			t.Errorf("normalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
