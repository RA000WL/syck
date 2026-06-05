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

func TestRuleLoaderVersionGate(t *testing.T) {
	dir := t.TempDir()
	yaml := "rules:\n  - name: a\n    severity: LOW\n    pattern: a\n    version: \"99\"\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromDir(dir); err == nil {
		t.Error("expected version gate to reject version 99, got nil")
	}
}

func TestRuleLoaderVersionGateAccepts(t *testing.T) {
	dir := t.TempDir()
	yaml := "rules:\n  - name: a\n    severity: LOW\n    pattern: a\n    version: \"1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromDir(dir); err != nil {
		t.Errorf("expected version 1 to be accepted, got %v", err)
	}
}
