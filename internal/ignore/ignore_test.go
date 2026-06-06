package ignore

import (
	"os"
	"path/filepath"
	"regexp"
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

func TestLoadIgnoreFile_Fingerprints(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".syckignore")
	content := "# comment\n\nabc123  # rule in file.txt:1\ndef456\n\n# another comment\nxyz789\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	set, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Fingerprints) != 3 {
		t.Fatalf("Expected 3 fingerprints, got %d", len(set.Fingerprints))
	}
	for _, fp := range []string{"abc123", "def456", "xyz789"} {
		if !set.Fingerprints[fp] {
			t.Fatalf("Expected fingerprint %q in ignore set", fp)
		}
	}
	if len(set.Patterns) != 0 {
		t.Fatalf("Expected 0 patterns, got %d", len(set.Patterns))
	}
}

func TestLoadIgnoreFile_Patterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".syckignore")
	content := "re:googleapis\\.com\nre:\\.example\\.com\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	set, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Patterns) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(set.Patterns))
	}
	if !set.Patterns[0].MatchString("https://fonts.googleapis.com") {
		t.Error("pattern 0 should match googleapis URL")
	}
	if !set.Patterns[1].MatchString("foo.example.com/bar") {
		t.Error("pattern 1 should match example.com")
	}
}

func TestLoadIgnoreFile_Mixed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".syckignore")
	content := "abc123\nre:googleapis\\.com\ndef456\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	set, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Fingerprints) != 2 {
		t.Errorf("fingerprints = %d, want 2", len(set.Fingerprints))
	}
	if len(set.Patterns) != 1 {
		t.Errorf("patterns = %d, want 1", len(set.Patterns))
	}
}

func TestLoadIgnoreFile_BadPattern(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".syckignore")
	if err := os.WriteFile(path, []byte("re:[unclosed"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIgnoreFile(path); err == nil {
		t.Fatal("Expected error for invalid regex")
	}
}

func TestLoadIgnoreFileMissing(t *testing.T) {
	_, err := LoadIgnoreFile("/nonexistent/.syckignore")
	if err == nil {
		t.Fatal("Expected error for missing file")
	}
}

func TestFilter_Fingerprint(t *testing.T) {
	f1 := finding.Finding{RuleName: "rule1", Secret: "s1", File: "a.txt"}
	f2 := finding.Finding{RuleName: "rule2", Secret: "s2", File: "b.txt"}
	f3 := finding.Finding{RuleName: "rule3", Secret: "s3", File: "c.txt"}

	set := &IgnoreSet{
		Fingerprints: map[string]bool{Fingerprint(f2): true},
	}

	result := Filter([]finding.Finding{f1, f2, f3}, set)
	if len(result) != 2 {
		t.Fatalf("Expected 2 findings after filter, got %d", len(result))
	}
	if result[0].RuleName != "rule1" || result[1].RuleName != "rule3" {
		t.Fatalf("Wrong findings retained: %v", result)
	}
}

func TestFilter_PatternMatchesSecret(t *testing.T) {
	f1 := finding.Finding{RuleName: "rule1", Secret: "https://fonts.googleapis.com/css?family=abc", File: "a.txt"}
	f2 := finding.Finding{RuleName: "rule2", Secret: "AKIAIOSFODNN7EXAMPLE", File: "b.txt"}

	set := &IgnoreSet{
		Patterns: compilePats(t, `googleapis\.com`),
	}
	result := Filter([]finding.Finding{f1, f2}, set)
	if len(result) != 1 || result[0].RuleName != "rule2" {
		t.Fatalf("Expected only rule2 to survive, got %+v", result)
	}
}

func TestFilter_PatternMatchesFile(t *testing.T) {
	f1 := finding.Finding{RuleName: "rule1", Secret: "x", File: "vendor/lib.go"}
	f2 := finding.Finding{RuleName: "rule2", Secret: "y", File: "src/main.go"}

	set := &IgnoreSet{
		Patterns: compilePats(t, `^vendor/`),
	}
	result := Filter([]finding.Finding{f1, f2}, set)
	if len(result) != 1 || result[0].RuleName != "rule2" {
		t.Fatalf("Expected only rule2 to survive, got %+v", result)
	}
}

func TestFilter_NilSet(t *testing.T) {
	findings := []finding.Finding{{RuleName: "r", Secret: "s", File: "f"}}
	result := Filter(findings, nil)
	if len(result) != 1 {
		t.Fatalf("nil set should be a no-op; got %d", len(result))
	}
}

func TestFilterEmpty(t *testing.T) {
	result := Filter(nil, &IgnoreSet{})
	if len(result) != 0 {
		t.Fatalf("Expected 0, got %d", len(result))
	}
}

func compilePats(t *testing.T, p ...string) []*regexp.Regexp {
	t.Helper()
	out := make([]*regexp.Regexp, 0, len(p))
	for _, s := range p {
		r, err := regexp.Compile(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
