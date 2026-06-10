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

func TestCacheSchemaVerdictsAndWeights(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Verify verdicts table exists by inserting a dummy row
	// (we need a finding first, so record one)
	fp := Fingerprint("test_rule", "secret123", "test.js")
	_, err = c.Record(fp)
	if err != nil {
		t.Fatal(err)
	}

	// Now insert a verdict
	err = c.Verdict(fp, "fp")
	if err != nil {
		t.Fatal(err)
	}

	// Verify learned_weights table exists by querying it
	_, err = c.db.Exec(`SELECT rule_name, file_pattern, tp_weighted, fp_weighted, sample_count, tier, modifier, updated_at FROM learned_weights`)
	if err != nil {
		t.Fatal("learned_weights table missing:", err)
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
