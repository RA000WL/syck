// Package sqliteutil opens SQLite databases with the tuning that syck's caches
// need: a single-writer connection cap, WAL, and a busy timeout. It exists so
// the tuning and its rationale live in one place instead of once per opener.
package sqliteutil

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// Open opens the SQLite database at path with the pool hardened for concurrent
// use. SQLite allows a single writer at a time, and crawl/scan workers hit
// their caches from every goroutine, so the pool is capped at one connection:
// writers serialize on the connection instead of racing and losing to
// SQLITE_BUSY. WAL keeps readers off the writer's lock and busy_timeout makes
// a contended write wait instead of failing instantly. journal_mode is a
// persistent property of the database file; busy_timeout is per-connection,
// which the single-connection cap makes stable for the pool's lifetime.
//
// The pragmas are best-effort and never fail the open. Switching journal mode
// needs a write lock, so a read-only cache file reports "attempt to write a
// readonly database" and SQLite quietly keeps the previous journal mode — the
// pre-hardening behavior. Every caller already treats an unusable cache as "no
// cache" rather than a fatal error, so failing here would only turn a working
// (if write-less) cache into a disabled one. Accordingly the returned error
// comes from sql.Open alone; a pragma failure is never promoted to one.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	tune(db)
	return db, nil
}

func tune(db *sql.DB) {
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
	} {
		db.Exec(pragma) // errors deliberately ignored, see Open
	}
}
