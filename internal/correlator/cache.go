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
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_fingerprint ON findings(fingerprint)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create index: %w", err)
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
	now := time.Now().UTC().Format(time.RFC3339)
	var firstSeen string
	err = c.db.QueryRow(`SELECT first_seen FROM findings WHERE fingerprint = ?`, fingerprint).Scan(&firstSeen)
	if err == nil {
		_, err = c.db.Exec(`UPDATE findings SET last_seen = ? WHERE fingerprint = ?`, now, fingerprint)
		return false, err
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	_, err = c.db.Exec(`INSERT INTO findings (fingerprint, first_seen, last_seen) VALUES (?, ?, ?)`, fingerprint, now, now)
	if err != nil {
		return false, err
	}
	return true, nil
}
