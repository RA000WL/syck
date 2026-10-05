package scanner

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

func TestScanFile_ArchiveZeroMaxFileSize(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello TOKEN_ABCDEF12 world\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	yaml := "rules:\n  - name: token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"
	rs, err := rules.NewRuleLoader().LoadFromFile(writeTempYAML(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	// MaxFileSize intentionally left at the zero value: must not skip the archive.
	cfg := Config{Rules: rs, MinSeverity: finding.ParseSeverity("LOW"), ScanArchives: true}
	got, err := ScanFile(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatalf("expected findings from archived member with zero MaxFileSize, got 0")
	}
}
