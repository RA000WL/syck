package scanner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

// scanReaderOnContent writes content to a temp file, opens it as *os.File,
// and runs ScanReader (the stdin path).
func scanReaderOnContent(t *testing.T, content string, cfg Config) []finding.Finding {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	findings, err := ScanReader(f, cfg)
	if err != nil {
		t.Fatalf("ScanReader error: %v", err)
	}
	return findings
}

func TestScanReaderDecodesBase64(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	payload := strings.Repeat("A", 600) + " " + secret
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	line := `const blob = "` + encoded + "\"\n"

	cfg := Config{Rules: loadMinimalRules(t), DecodeBase64: true}
	findings := scanReaderOnContent(t, line, cfg)
	if !hasSecret(findings, secret) {
		t.Fatalf("ScanReader with DecodeBase64: want secret %q, got: %+v", secret, findings)
	}
}

func TestScanReaderDecodesDoubleBase64(t *testing.T) {
	cfg := Config{Rules: loadMinimalRules(t), DecodeDoubleBase64: true}
	findings := scanReaderOnContent(t, doubleBase64Fixture(newDecoderSecret)+"\n", cfg)
	if !hasRulePrefixWithSecret(findings, "doublebase64_", newDecoderSecret) {
		t.Fatalf("ScanReader with DecodeDoubleBase64: want doublebase64_ finding, got: %+v", findings)
	}
}
