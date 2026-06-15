package crawler

import (
	"crypto/sha256"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type URLCache struct {
	db *sql.DB
}

func OpenURLCache(path string) (*URLCache, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open url cache db: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS crawled_urls (
		url_hash TEXT PRIMARY KEY,
		url TEXT NOT NULL,
		status_code INTEGER NOT NULL,
		content_hash TEXT NOT NULL,
		first_seen TEXT NOT NULL DEFAULT (datetime('now')),
		last_seen TEXT NOT NULL DEFAULT (datetime('now'))
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create crawled_urls table: %w", err)
	}
	return &URLCache{db: db}, nil
}

func (c *URLCache) Close() error {
	return c.db.Close()
}

func URLHash(url string) string {
	h := sha256.Sum256([]byte(url))
	return fmt.Sprintf("%x", h[:16])
}

func ContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h[:16])
}

// IsSeen returns true if the URL was previously fetched successfully (status 200).
func (c *URLCache) IsSeen(url string) bool {
	var count int
	err := c.db.QueryRow(
		"SELECT COUNT(*) FROM crawled_urls WHERE url_hash = ? AND status_code = 200",
		URLHash(url),
	).Scan(&count)
	return err == nil && count > 0
}

// GetContentHash returns the content hash for a previously fetched URL, or empty string if not cached.
func (c *URLCache) GetContentHash(url string) string {
	var hash string
	err := c.db.QueryRow(
		"SELECT content_hash FROM crawled_urls WHERE url_hash = ? AND status_code = 200",
		URLHash(url),
	).Scan(&hash)
	if err != nil {
		return ""
	}
	return hash
}

// Record stores a crawled URL result. Returns true if this is a new URL.
func (c *URLCache) Record(url string, statusCode int, content string) (isNew bool, err error) {
	uHash := URLHash(url)
	cHash := ContentHash(content)

	_, err = c.db.Exec(
		`INSERT INTO crawled_urls (url_hash, url, status_code, content_hash, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))`,
		uHash, url, statusCode, cHash,
	)
	if err != nil {
		_, updateErr := c.db.Exec(
			"UPDATE crawled_urls SET last_seen = datetime('now'), status_code = ?, content_hash = ? WHERE url_hash = ?",
			statusCode, cHash, uHash,
		)
		if updateErr != nil {
			return false, updateErr
		}
		return false, nil
	}
	return true, nil
}

// Count returns the total number of cached URLs.
func (c *URLCache) Count() (int, error) {
	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM crawled_urls").Scan(&count)
	return count, err
}
