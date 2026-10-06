package correlator

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestMtimeCache(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mtime.db")

	c, err := OpenCache(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	// File not yet tracked → should not skip
	if c.ShouldSkipFile("/test/file.js", 1000) {
		t.Fatal("expected ShouldSkipFile=false for untracked file")
	}

	// Record mtime
	if err := c.RecordFileMtime("/test/file.js", 1000); err != nil {
		t.Fatalf("record mtime: %v", err)
	}

	// Same mtime → should skip
	if !c.ShouldSkipFile("/test/file.js", 1000) {
		t.Fatal("expected ShouldSkipFile=true for same mtime")
	}

	// Different mtime → should not skip
	if c.ShouldSkipFile("/test/file.js", 2000) {
		t.Fatal("expected ShouldSkipFile=false for changed mtime")
	}

	// Update mtime
	if err := c.RecordFileMtime("/test/file.js", 2000); err != nil {
		t.Fatalf("update mtime: %v", err)
	}
	if !c.ShouldSkipFile("/test/file.js", 2000) {
		t.Fatal("expected ShouldSkipFile=true after mtime update")
	}
}

// TestOpenCacheAppliesPragmas locks in the concurrency hardening: WAL journal
// (readers never block the writer), a busy timeout (a contended write waits
// instead of failing instantly), and a single-writer connection cap so scan
// worker goroutines serialize on one SQLite connection.
func TestOpenCacheAppliesPragmas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragma.db")

	c, err := OpenCache(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	var mode string
	if err := c.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}

	var busyTimeout int
	if err := c.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}

	if got := c.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

// TestOpenCachePragmaFailureIsNotFatal locks in graceful degradation: switching
// journal mode needs a write lock, so a read-only database file makes the WAL
// pragma fail. That must degrade to the pre-hardening journal mode, not turn a
// previously openable cache into an error.
func TestOpenCachePragmaFailureIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dbPath := filepath.Join(t.TempDir(), "readonly.db")

	// Build a complete schema with the raw driver so the fixture is not in
	// WAL mode (a WAL database needs a writable -shm file just to be read).
	seed, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE findings (fingerprint TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, rule_name TEXT DEFAULT '', file TEXT DEFAULT '', secret TEXT DEFAULT '')`,
		`CREATE TABLE verdicts (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, verdict TEXT NOT NULL, created_at TEXT)`,
		`CREATE TABLE learned_weights (rule_name TEXT NOT NULL, file_pattern TEXT NOT NULL, tp_weighted REAL NOT NULL, fp_weighted REAL NOT NULL, sample_count INTEGER NOT NULL, tier INTEGER NOT NULL, modifier REAL NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (rule_name, file_pattern))`,
		`CREATE TABLE file_mtimes (file_path TEXT PRIMARY KEY, mtime INTEGER NOT NULL)`,
		`INSERT INTO file_mtimes (file_path, mtime) VALUES ('/a.js', 1)`,
	} {
		if _, err := seed.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	if err := os.Chmod(dbPath, 0444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dbPath, 0644) })

	c, err := OpenCache(dbPath)
	if err != nil {
		t.Fatalf("open read-only cache: %v", err)
	}
	defer c.Close()

	// Reads still work; the WAL pragma was skipped, not fatal.
	if !c.ShouldSkipFile("/a.js", 1) {
		t.Error("expected cached mtime to still be readable on read-only db")
	}
	if got := c.db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1 (still capped)", got)
	}
}

// TestConcurrentRecordFileMtime reproduces the scan-worker pattern: many
// goroutines writing mtimes concurrently. Before WAL + busy_timeout this
// returned "database is locked" and the write was silently dropped, degrading
// the incremental-scan cache.
func TestConcurrentRecordFileMtime(t *testing.T) {
	const (
		workers = 8
		writes  = 50
	)

	dbPath := filepath.Join(t.TempDir(), "concurrent.db")
	c, err := OpenCache(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close()

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				path := fmt.Sprintf("/repo/worker-%d/file-%d.js", worker, i)
				if err := c.RecordFileMtime(path, int64(1000+i)); err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()

	for _, err := range errs {
		if strings.Contains(err.Error(), "database is locked") {
			t.Errorf("concurrent write failed with lock contention: %v", err)
			continue
		}
		t.Errorf("concurrent RecordFileMtime: %v", err)
	}
	if len(errs) > 0 {
		t.Errorf("got %d errors from %d concurrent writes, want 0", len(errs), workers*writes)
	}

	// Every write must have landed — a dropped write silently degrades the cache.
	var count int
	if err := c.db.QueryRow("SELECT COUNT(*) FROM file_mtimes").Scan(&count); err != nil {
		t.Fatalf("count file_mtimes: %v", err)
	}
	if count != workers*writes {
		t.Errorf("file_mtimes rows = %d, want %d", count, workers*writes)
	}
}
