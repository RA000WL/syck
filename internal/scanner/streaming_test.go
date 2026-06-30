package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/rules"
)

func loadDefaultRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	return rs
}

func loadMinimalRules(t *testing.T) *rules.RuleSet {
	t.Helper()
	yaml := `rules:
  - name: aws_access_key
    severity: HIGH
    pattern: 'AKIA[0-9A-Z]{16}'
`
	rs, err := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	if err != nil {
		t.Fatalf("load minimal rules: %v", err)
	}
	return rs
}

func TestScanFileStreaming_MegaLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")

	secret := "AKIAIOSFODNN7EXAMPLE"
	// Pad to >1MB to trigger streaming path, with secret on its own line
	padding := strings.Repeat("x", 1024*1024)
	payload := padding + "\n" + secret + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Workers:     1,
		MaxFileSize: 100 << 20,
		Rules:       loadMinimalRules(t),
	}

	findings, err := ScanFile(path, cfg)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Secret == secret {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find AWS key %q, got %d findings: %+v", secret, len(findings), findings)
	}
}

func TestScanFileFallback_ErrTooLong(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.txt")

	secret := "AKIAIOSFODNN7EXAMPLE"
	// Line > 10MB (scanner buffer) triggers bufio.ErrTooLong -> scanFileFallback
	bigLine := strings.Repeat("A", 11*1024*1024) + secret
	if err := os.WriteFile(path, []byte(bigLine), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Workers:     1,
		MaxFileSize: 100 << 20,
		Rules:       loadMinimalRules(t),
		Debug:       true,
	}

	findings, err := ScanFile(path, cfg)
	if err != nil {
		t.Fatalf("ScanFile error (fallback path should not error): %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Secret == secret {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find AWS key %q via fallback, got %d findings: %+v", secret, len(findings), findings)
	}
}

func TestScanFile_StandardFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "normal.txt")

	content := `package config
var aws_key = "AKIAIOSFODNN7EXAMPLE"
var password = "super_secret_password_123"
# nothing sensitive here
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Workers:     1,
		MaxFileSize: 100 << 20,
		Rules:       loadDefaultRules(t),
	}

	findings, err := ScanFile(path, cfg)
	if err != nil {
		t.Fatalf("ScanFile error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding in standard file")
	}

	foundAWS := false
	for _, f := range findings {
		if strings.Contains(f.Secret, "AKIA") {
			foundAWS = true
			break
		}
	}
	if !foundAWS {
		t.Errorf("expected AWS key in findings, got: %+v", findings)
	}
}
