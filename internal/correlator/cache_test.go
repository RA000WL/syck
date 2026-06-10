package correlator

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/RA000WL/syck/internal/adaptive"
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

func TestCacheRecomputeWeights(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	fp1 := Fingerprint("rule_a", "secret1", "test.js")
	fp2 := Fingerprint("rule_a", "secret2", "test.js")
	c.RecordWithMeta(fp1, "rule_a", "secret1", "test.js")
	c.RecordWithMeta(fp2, "rule_a", "secret2", "test.js")

	c.Verdict(fp1, "fp")
	c.Verdict(fp1, "fp")
	c.Verdict(fp2, "tp")

	err = c.RecomputeWeights()
	if err != nil {
		t.Fatal(err)
	}

	var count int
	c.db.QueryRow("SELECT COUNT(*) FROM learned_weights").Scan(&count)
	if count == 0 {
		t.Error("expected learned_weights to have rows after recompute")
	}
}

func TestCacheLoadWeights(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	fp1 := Fingerprint("rule_a", "secret1", "test.js")
	c.RecordWithMeta(fp1, "rule_a", "secret1", "test.js")
	c.Verdict(fp1, "fp")
	c.RecomputeWeights()

	store, err := c.LoadWeights()
	if err != nil {
		t.Fatal(err)
	}
	w := store.Get("rule_a", "*.js")
	if w == nil {
		t.Error("expected weight for rule_a+test pattern")
	}
}

func TestCacheGetWeightedStats(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	fp1 := Fingerprint("rule_b", "secret1", "src/main.go")
	c.RecordWithMeta(fp1, "rule_b", "secret1", "src/main.go")
	c.Verdict(fp1, "tp")
	c.RecomputeWeights()

	rows, err := c.GetWeightedStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Error("expected at least one weighted stat row")
	}
}

func TestAdaptiveFullFlow(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. Record findings with metadata
	fp1 := Fingerprint("generic_api_key", "sk_test123", "test/config.js")
	fp2 := Fingerprint("generic_api_key", "sk_test456", "test/config.js")
	fp3 := Fingerprint("generic_api_key", "sk_prod789", "src/app.js")
	c.RecordWithMeta(fp1, "generic_api_key", "sk_test123", "test/config.js")
	c.RecordWithMeta(fp2, "generic_api_key", "sk_test456", "test/config.js")
	c.RecordWithMeta(fp3, "generic_api_key", "sk_prod789", "src/app.js")

	// 2. Verdicts: 2 FP on test files, 1 TP on source
	c.Verdict(fp1, "fp")
	c.Verdict(fp2, "fp")
	c.Verdict(fp3, "tp")

	// 3. Recompute
	err = c.RecomputeWeights()
	if err != nil {
		t.Fatal(err)
	}

	// 4. Load weights
	store, err := c.LoadWeights()
	if err != nil {
		t.Fatal(err)
	}

	// 5. Test file pattern should have learned weight (negative modifier — more FPs)
	testW := store.Get("generic_api_key", "*/test/*")
	if testW == nil {
		t.Fatal("expected learned weight for generic_api_key + */test/*")
	}
	if testW.Modifier >= 0 {
		t.Errorf("test pattern expected negative modifier (2 FP, 0 TP), got %f", testW.Modifier)
	}

	// 6. Source file pattern should have positive modifier (1 TP, 0 FP)
	srcW := store.Get("generic_api_key", "*.js")
	if srcW == nil {
		t.Fatal("expected learned weight for generic_api_key + *.js")
	}
	if srcW.Modifier <= 0 {
		t.Errorf("source pattern expected positive modifier (0 FP, 1 TP), got %f", srcW.Modifier)
	}

	// 7. Verify tier is Experimental (only 2-3 samples)
	if testW.Tier != adaptive.TierExperimental {
		t.Errorf("expected Experimental tier at 2 samples, got %v", testW.Tier)
	}

	// 8. Verify stats
	stats, err := c.GetWeightedStats()
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) < 2 {
		t.Errorf("expected 2+ stat rows, got %d", len(stats))
	}

	// 9. Verify total verdicts
	total, err := c.TotalVerdicts()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected 3 total verdicts, got %d", total)
	}
}

func TestAdaptiveBatchVerdicts(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Record 20 findings and mark all as FP
	for i := 0; i < 20; i++ {
		fp := Fingerprint("noisy_rule", fmt.Sprintf("secret_%d", i), fmt.Sprintf("test/file_%d.js", i))
		c.RecordWithMeta(fp, "noisy_rule", fmt.Sprintf("secret_%d", i), fmt.Sprintf("test/file_%d.js", i))
		c.Verdict(fp, "fp")
	}

	err = c.RecomputeWeights()
	if err != nil {
		t.Fatal(err)
	}

	store, err := c.LoadWeights()
	if err != nil {
		t.Fatal(err)
	}

	w := store.Get("noisy_rule", "*/test/*")
	if w == nil {
		t.Fatal("expected weight for noisy_rule")
	}

	// 20 FPs should produce negative modifier
	if w.Modifier >= 0 {
		t.Errorf("20 FPs should have negative modifier, got %f", w.Modifier)
	}

	// Should be at Learning tier (10-49 samples)
	if w.Tier != adaptive.TierLearning {
		t.Errorf("expected Learning tier at 20 samples, got %v", w.Tier)
	}
}
