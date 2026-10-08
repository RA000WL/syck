package sqliteutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenAppliesPragmas locks in the concurrency hardening every caller
// inherits from one place: WAL journal (readers never block the writer), a busy
// timeout (a contended write waits instead of failing instantly), and a
// single-writer connection cap so worker goroutines serialize on one SQLite
// connection.
func TestOpenAppliesPragmas(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pragma.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}

	var busyTimeout int
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}

	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1", got)
	}
}

// TestOpenPragmaFailureIsNotFatal locks in graceful degradation: switching
// journal mode needs a write lock, so a read-only database file makes the WAL
// pragma fail. That must degrade to the pre-hardening journal mode, not turn a
// previously openable database into an error.
func TestOpenPragmaFailureIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dbPath := filepath.Join(t.TempDir(), "readonly.db")

	// Seed with the raw driver so the fixture is not in WAL mode (a WAL
	// database needs a writable -shm file just to be read).
	seed, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE t (k TEXT PRIMARY KEY, v INTEGER NOT NULL)`,
		`INSERT INTO t (k, v) VALUES ('/a.js', 1)`,
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

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open read-only db: %v", err)
	}
	defer db.Close()

	// Reads still work; the WAL pragma was skipped, not fatal.
	var v int
	if err := db.QueryRow("SELECT v FROM t WHERE k = ?", "/a.js").Scan(&v); err != nil {
		t.Fatalf("read from read-only db: %v", err)
	}
	if v != 1 {
		t.Errorf("v = %d, want 1", v)
	}
	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("MaxOpenConnections = %d, want 1 (still capped)", got)
	}
}
