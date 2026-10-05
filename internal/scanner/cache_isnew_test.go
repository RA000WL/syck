package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RA000WL/syck/internal/finding"
)

const cacheDBTestRules = "rules:\n  - name: test_token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"

// countSecret returns how many findings carry the fixture secret.
func countSecret(findings []finding.Finding, secret string) int {
	n := 0
	for _, f := range findings {
		if f.Secret == secret {
			n++
		}
	}
	return n
}

func countNew(findings []finding.Finding, secret string) int {
	n := 0
	for _, f := range findings {
		if f.Secret == secret && f.IsNew {
			n++
		}
	}
	return n
}

// A secret used on three lines yields three occurrences, but they share one
// fingerprint (RuleName|Secret|File) so only the first INSERT reports isNew.
// Every occurrence must still be flagged new on first sight, otherwise --diff
// shows 1 new + 2 known for a single secret.
func TestIsNewBackFilledAcrossOccurrences(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.txt")
	content := "a = TOKEN_ABCDEF12\nb = TOKEN_ABCDEF12\nc = TOKEN_ABCDEF12\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Rules:       loadTestRuleSet(t, cacheDBTestRules),
		MinSeverity: finding.ParseSeverity("LOW"),
		Workers:     2,
		CacheDB:     filepath.Join(dir, "cache.db"),
	}

	first, err := ScanPaths([]string{dir}, cfg)
	if err != nil {
		t.Fatalf("first ScanPaths: %v", err)
	}
	const secret = "TOKEN_ABCDEF12"
	if got := countSecret(first, secret); got != 3 {
		t.Fatalf("first run produced %d occurrences of the fixture secret, want 3", got)
	}
	if got := countNew(first, secret); got != 3 {
		t.Errorf("first run: %d of 3 occurrences marked IsNew, want 3 (only the first is a cache INSERT)", got)
	}

	// Bump mtime past the skip cache so the second run actually re-scans.
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(target, future, future); err != nil {
		t.Fatal(err)
	}

	second, err := ScanPaths([]string{dir}, cfg)
	if err != nil {
		t.Fatalf("second ScanPaths: %v", err)
	}
	if got := countSecret(second, secret); got != 3 {
		t.Fatalf("second run produced %d occurrences, want 3", got)
	}
	if got := countNew(second, secret); got != 0 {
		t.Errorf("second run: %d of 3 occurrences marked IsNew, want 0 (fingerprint already cached)", got)
	}
}
