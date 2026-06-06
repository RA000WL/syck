package ignore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
)

func TestFingerprint(t *testing.T) {
	f := finding.Finding{
		RuleName: "test_rule",
		Secret:   "secret123",
		File:     "file.txt",
	}
	fp1 := Fingerprint(f)
	fp2 := Fingerprint(f)
	if fp1 != fp2 {
		t.Fatalf("Fingerprint not deterministic: %s != %s", fp1, fp2)
	}
	if len(fp1) != 64 {
		t.Fatalf("Expected 64-char hex, got %d chars", len(fp1))
	}

	f2 := finding.Finding{
		RuleName: "test_rule",
		Secret:   "secret999",
		File:     "file.txt",
	}
	fp3 := Fingerprint(f2)
	if fp1 == fp3 {
		t.Fatal("Different inputs produced same fingerprint")
	}
}

func TestLoadIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".syckignore")
	content := "# comment\n\nabc123  # rule in file.txt:1\ndef456\n\n# another comment\nxyz789\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	ignoreSet, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ignoreSet) != 3 {
		t.Fatalf("Expected 3 fingerprints, got %d", len(ignoreSet))
	}
	for _, fp := range []string{"abc123", "def456", "xyz789"} {
		if !ignoreSet[fp] {
			t.Fatalf("Expected fingerprint %q in ignore set", fp)
		}
	}
}

func TestLoadIgnoreFileMissing(t *testing.T) {
	_, err := LoadIgnoreFile("/nonexistent/.syckignore")
	if err == nil {
		t.Fatal("Expected error for missing file")
	}
}

func TestFilter(t *testing.T) {
	f1 := finding.Finding{RuleName: "rule1", Secret: "s1", File: "a.txt"}
	f2 := finding.Finding{RuleName: "rule2", Secret: "s2", File: "b.txt"}
	f3 := finding.Finding{RuleName: "rule3", Secret: "s3", File: "c.txt"}

	findings := []finding.Finding{f1, f2, f3}
	ignoreSet := map[string]bool{
		Fingerprint(f2): true,
	}

	result := Filter(findings, ignoreSet)
	if len(result) != 2 {
		t.Fatalf("Expected 2 findings after filter, got %d", len(result))
	}
	if result[0].RuleName != "rule1" || result[1].RuleName != "rule3" {
		t.Fatalf("Wrong findings retained: %v", result)
	}
}

func TestFilterEmpty(t *testing.T) {
	result := Filter(nil, map[string]bool{})
	if len(result) != 0 {
		t.Fatalf("Expected 0, got %d", len(result))
	}
}
