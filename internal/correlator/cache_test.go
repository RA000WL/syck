package correlator

import (
	"path/filepath"
	"testing"
)

func TestCache(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	c, err := OpenCache(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	fp := Fingerprint("rule", "secret", "file.txt")
	isNew, err := c.Record(fp)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !isNew {
		t.Fatal("expected isNew=true for first record")
	}

	isNew, err = c.Record(fp)
	if err != nil {
		t.Fatalf("record2: %v", err)
	}
	if isNew {
		t.Fatal("expected isNew=false for duplicate")
	}
}

func TestFingerprint(t *testing.T) {
	fp1 := Fingerprint("a", "b", "c")
	fp2 := Fingerprint("a", "b", "c")
	fp3 := Fingerprint("a", "b", "d")
	if fp1 != fp2 {
		t.Fatal("same inputs should produce same fingerprint")
	}
	if fp1 == fp3 {
		t.Fatal("different file should produce different fingerprint")
	}
}
