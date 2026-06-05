package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectorWalk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "x"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(Config{Workers: 2})
	files, err := c.Walk(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range files {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 file, got %d", count)
	}
}
