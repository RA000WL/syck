package correlator

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"github.com/RA000WL/syck/internal/adaptive"
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
	// Migrate findings table — add rule_name, file, secret columns
	for _, col := range []string{
		`ALTER TABLE findings ADD COLUMN rule_name TEXT DEFAULT ''`,
		`ALTER TABLE findings ADD COLUMN file TEXT DEFAULT ''`,
		`ALTER TABLE findings ADD COLUMN secret TEXT DEFAULT ''`,
	} {
		db.Exec(col) // ignore errors for existing columns
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

// RecordWithMeta records a finding with full metadata for adaptive learning.
func (c *Cache) RecordWithMeta(fingerprint, ruleName, secret, file string) (isNew bool, err error) {
	_, err = c.db.Exec(
		`INSERT INTO findings (fingerprint, first_seen, last_seen, rule_name, secret, file)
		 VALUES (?, datetime('now'), datetime('now'), ?, ?, ?)`,
		fingerprint, ruleName, secret, file,
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

// RecomputeWeights rebuilds the learned_weights table from verdicts + findings.
func (c *Cache) RecomputeWeights() error {
	rows, err := c.db.Query(`
		SELECT f.rule_name, f.file, v.verdict, v.created_at
		FROM verdicts v
		JOIN findings f ON v.fingerprint = f.fingerprint
		WHERE f.rule_name != ''
	`)
	if err != nil {
		return fmt.Errorf("query verdicts: %w", err)
	}
	defer rows.Close()

	type comboKey struct {
		ruleName    string
		filePattern string
	}
	type comboData struct {
		verdicts []adaptive.Verdict
	}

	combos := make(map[comboKey]*comboData)
	for rows.Next() {
		var ruleName, file, verdict, createdAt string
		if err := rows.Scan(&ruleName, &file, &verdict, &createdAt); err != nil {
			return fmt.Errorf("scan verdict row: %w", err)
		}
		ts, _ := time.Parse("2006-01-02 15:04:05", createdAt)
		fp := adaptive.ExtractFilePattern(file)
		key := comboKey{ruleName: ruleName, filePattern: fp}
		if _, ok := combos[key]; !ok {
			combos[key] = &comboData{}
		}
		combos[key].verdicts = append(combos[key].verdicts, adaptive.Verdict{
			Fingerprint: "",
			Verdict:     verdict,
			CreatedAt:   ts,
		})
	}

	if _, err := c.db.Exec("DELETE FROM learned_weights"); err != nil {
		return fmt.Errorf("clear learned_weights: %w", err)
	}

	for key, data := range combos {
		weightedFP, weightedTP, sampleCount := adaptive.ComputeWeightedStats(data.verdicts)
		modifier := adaptive.ComputeModifierFromStats(key.ruleName, weightedFP, weightedTP, sampleCount)
		tier := adaptive.ClassifyTier(sampleCount)
		if _, err := c.db.Exec(
			`INSERT INTO learned_weights (rule_name, file_pattern, tp_weighted, fp_weighted, sample_count, tier, modifier, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			key.ruleName, key.filePattern, weightedTP, weightedFP, sampleCount, int(tier), modifier,
		); err != nil {
			return fmt.Errorf("insert learned weight: %w", err)
		}
	}
	return nil
}

// LoadWeights returns all learned weights as an in-memory store.
func (c *Cache) LoadWeights() (*adaptive.LearnedWeightStore, error) {
	store := adaptive.NewLearnedWeightStore()
	rows, err := c.db.Query("SELECT rule_name, file_pattern, tp_weighted, fp_weighted, sample_count FROM learned_weights")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ruleName, filePattern string
		var tpW, fpW float64
		var sampleCount int
		if err := rows.Scan(&ruleName, &filePattern, &tpW, &fpW, &sampleCount); err != nil {
			return nil, err
		}
		store.Set(ruleName, filePattern, tpW, fpW, sampleCount)
	}
	return store, nil
}

// WeightedStatRow is a row from the stats query.
type WeightedStatRow struct {
	RuleName        string
	FilePattern     string
	TPCount         int
	FPCount         int
	SmoothedFPRatio float64
	Modifier        float64
	TierLabel       string
}

// GetWeightedStats returns stats for all learned weights.
func (c *Cache) GetWeightedStats() ([]WeightedStatRow, error) {
	rows, err := c.db.Query(`
		SELECT rule_name, file_pattern, tp_weighted, fp_weighted, sample_count, tier, modifier
		FROM learned_weights
		ORDER BY ABS(modifier) DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []WeightedStatRow
	for rows.Next() {
		var r WeightedStatRow
		var tier int
		var tpW, fpW float64
		var sampleCount int
		if err := rows.Scan(&r.RuleName, &r.FilePattern, &tpW, &fpW, &sampleCount, &tier, &r.Modifier); err != nil {
			return nil, err
		}
		r.TPCount = int(tpW)
		r.FPCount = int(fpW)
		r.TierLabel = adaptive.Tier(tier).Label()
		r.SmoothedFPRatio = (fpW + 5.0) / (fpW + tpW + 10.0)
		results = append(results, r)
	}
	return results, nil
}
