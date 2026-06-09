package correlator

import (
	"crypto/sha256"
	"database/sql"
	"fmt"

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
