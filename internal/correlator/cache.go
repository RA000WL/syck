package correlator

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Cache struct {
	db *sql.DB
}

func OpenCache(path string) (*Cache, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open cache db: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS findings (
		fingerprint TEXT PRIMARY KEY,
		first_seen TEXT NOT NULL,
		last_seen TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create cache table: %w", err)
	}
	// New: verdicts table
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS verdicts (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		fingerprint TEXT NOT NULL,
		verdict     TEXT NOT NULL CHECK(verdict IN ('tp', 'fp')),
		created_at  TEXT NOT NULL DEFAULT (datetime('now')),
		FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint)
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create verdicts table: %w", err)
	}
	// New: learned_weights table
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS learned_weights (
		rule_name    TEXT NOT NULL,
		file_pattern TEXT NOT NULL,
		tp_weighted  REAL NOT NULL,
		fp_weighted  REAL NOT NULL,
		sample_count INTEGER NOT NULL,
		tier         INTEGER NOT NULL,
		modifier     REAL NOT NULL,
		updated_at   TEXT NOT NULL,
		PRIMARY KEY (rule_name, file_pattern)
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create learned_weights table: %w", err)
	}
	return &Cache{db: db}, nil
}

func (c *Cache) Close() error {
	return c.db.Close()
}

func Fingerprint(ruleName, secret, file string) string {
	h := sha256.Sum256([]byte(ruleName + "|" + secret + "|" + file))
	return fmt.Sprintf("%x", h[:16])
}

func (c *Cache) Record(fingerprint string) (isNew bool, err error) {
	_, err = c.db.Exec(
		`INSERT INTO findings (fingerprint, first_seen, last_seen)
		 VALUES (?, datetime('now'), datetime('now'))`,
		fingerprint,
	)
	if err != nil {
		_, updateErr := c.db.Exec(
			"UPDATE findings SET last_seen = datetime('now') WHERE fingerprint = ?",
			fingerprint,
		)
		if updateErr != nil {
			return false, updateErr
		}
		return false, nil
	}
	return true, nil
}

// Verdict records a user verdict (tp/fp) for a finding.
func (c *Cache) Verdict(fingerprint, verdict string) error {
	if verdict != "tp" && verdict != "fp" {
		return fmt.Errorf("invalid verdict: %s (must be tp or fp)", verdict)
	}
	// Verify fingerprint exists in findings
	var exists int
	err := c.db.QueryRow("SELECT COUNT(*) FROM findings WHERE fingerprint = ?", fingerprint).Scan(&exists)
	if err != nil {
		return fmt.Errorf("query findings: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("fingerprint %s not found in findings", fingerprint)
	}
	_, err = c.db.Exec(
		`INSERT INTO verdicts (fingerprint, verdict, created_at) VALUES (?, ?, ?)`,
		fingerprint, verdict, time.Now().UTC().Format("2006-01-02 15:04:05"),
	)
	return err
}
