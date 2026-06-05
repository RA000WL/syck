package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempYAML(t *testing.T, s string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
