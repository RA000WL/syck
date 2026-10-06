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

func TestStreamingPoolBufferSize(t *testing.T) {
	bp := streamingBufPool.Get().(*[]byte)
	defer streamingBufPool.Put(bp)
	if len(*bp) != 256<<10 {
		t.Fatalf("pooled streaming buffer = %d bytes, want exactly %d (256KB)", len(*bp), 256<<10)
	}
}

func TestScanFileFallbackReportsFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mega.txt")

	secret := "AKIAIOSFODNN7EXAMPLE"
	// 2MB single-line file: exceeds the 256KB scanner buffer, so ScanFile
	// must still report the finding via the scanFileFallback path. This
	// guards the presence of the fallback, not the buffer size (see
	// TestStreamingPoolBufferSize for that).
	payload := strings.Repeat("A", 2*1024*1024) + secret + "\n"
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
		t.Fatalf("expected to find AWS key %q via fallback, got %d findings", secret, len(findings))
	}
}

func TestScanReaderHandlesLargeLine(t *testing.T) {
	// Regression guard: ScanReader must scan stdin lines larger than the
	// shared 256KB streaming pool buffer without erroring or losing findings.
	dir := t.TempDir()
	path := filepath.Join(dir, "stdin.txt")
	secret := "AKIAIOSFODNN7EXAMPLE"
	payload := strings.Repeat("A", 512*1024) + secret + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg := Config{Rules: loadMinimalRules(t)}
	findings, err := ScanReader(f, cfg)
	if err != nil {
		t.Fatalf("ScanReader must not fail on >256KB line: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.Secret == secret {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected finding %q from large stdin line, got %d findings", secret, len(findings))
	}
}

func BenchmarkScanReader(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "stdin.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("line of text\n", 100)), 0o644); err != nil {
		b.Fatal(err)
	}
	yaml := "rules:\n  - name: aws_access_key\n    severity: HIGH\n    pattern: 'AKIA[0-9A-Z]{16}'\n"
	yp := filepath.Join(b.TempDir(), "rules.yaml")
	if err := os.WriteFile(yp, []byte(yaml), 0o644); err != nil {
		b.Fatal(err)
	}
	rs, err := rules.NewRuleLoader().LoadFromFile(yp)
	if err != nil {
		b.Fatal(err)
	}
	cfg := Config{Rules: rs}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, err := os.Open(path)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ScanReader(f, cfg)
		f.Close()
		if err != nil {
			b.Fatal(err)
		}
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
