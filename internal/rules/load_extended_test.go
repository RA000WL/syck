package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuleLoaderDir(t *testing.T) {
	dir := t.TempDir()
	yaml := "rules:\n  - name: a\n    severity: LOW\n    pattern: a\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Name != "a" {
		t.Errorf("got %+v", rs.Rules)
	}
}
