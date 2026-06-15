# Adaptive Learning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add adaptive confidence learning to syck — users label findings as TP/FP via `syck verdict`, the scanner learns from this feedback over time, adjusting confidence scores with Bayesian smoothing, minimum evidence ramp-up, per-rule caps, and 90-day exponential decay.

**Architecture:** New `internal/adaptive` package for the learning engine (file pattern extraction, weighted stats, modifier computation, tier classification). Extended `internal/correlator/cache.go` with `verdicts` and `learned_weights` tables. New `cmd/verdict.go` CLI command. `--adaptive` flag on scan loads learned weights and applies modifiers to findings.

**Tech Stack:** Go, SQLite (modernc.org/sqlite), cobra, math, time

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `internal/adaptive/adaptive.go` | Core types, file pattern extraction, Bayesian smoothing, modifier computation, tier classification |
| Create | `internal/adaptive/adaptive_test.go` | Unit tests for all adaptive logic |
| Create | `cmd/verdict.go` | `syck verdict` CLI command with --stats |
| Create | `cmd/verdict_test.go` | Verdict command tests |
| Modify | `internal/correlator/cache.go` | Add verdicts + learned_weights tables, Verdict(), RecomputeWeights(), LoadWeights(), GetVerdictsForRule() |
| Modify | `internal/finding/finding.go` | Add AdaptiveModifier + LearningTier fields to Finding struct |
| Modify | `internal/confidence/confidence.go` | Add ScoreWithAdaptive() method |
| Modify | `internal/scanner/scanner.go` | Add Adaptive bool to Config |
| Modify | `internal/scanner/scan.go` | Load weights at scan start, apply modifier per finding |
| Modify | `cmd/scan.go` | Add --adaptive flag, pass to Config |
| Modify | `cmd/root.go` | Register verdictCmd |
| Modify | `internal/formatters/text.go` | Add adaptive=-27 [Mature] to output |
| Modify | `internal/formatters/json.go` | Add adaptive_modifier + learning_tier to JSON output |
| Modify | `internal/formatters/sarif.go` | Add adaptive_modifier + learning_tier to SARIF properties |
| Modify | `internal/formatters/markdown.go` | Add Adapt + Tier columns |
| Modify | `internal/formatters/csv.go` | Add Adapt + Tier columns |
| Modify | `internal/formatters/html.go` | Add Adapt + Tier columns |

---

## Task 1: Schema — Add verdicts + learned_weights tables

**Files:**
- Modify: `internal/correlator/cache.go`
- Test: `internal/correlator/cache_test.go`

- [ ] **Step 1: Write the failing test for new schema tables**

```go
// Add to internal/correlator/cache_test.go

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/correlator/ -run TestCacheSchemaVerdictsAndWeights -v`
Expected: FAIL — `Verdict` method does not exist

- [ ] **Step 3: Add schema + Verdict method to cache.go**

Add to `internal/correlator/cache.go`:

```go
import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ... existing Cache struct and OpenCache ...

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/correlator/ -run TestCacheSchemaVerdictsAndWeights -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/correlator/cache.go internal/correlator/cache_test.go
git commit -m "feat(adaptive): add verdicts + learned_weights schema to cache"
```

---

## Task 2: Core Adaptive Engine — Types, File Pattern Extraction, Tier Classification

**Files:**
- Create: `internal/adaptive/adaptive.go`
- Create: `internal/adaptive/adaptive_test.go`

- [ ] **Step 1: Write failing tests for file pattern extraction and tier classification**

```go
// internal/adaptive/adaptive_test.go
package adaptive

import "testing"

func TestExtractFilePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"src/components/App.js", "*.js"},
		{"test/config.test.js", "*/test/*"},
		{"tests/helpers.js", "*/test/*"},
		{"__tests__/unit.js", "*/test/*"},
		{"mocks/api.js", "*/mock/*"},
		{"__mocks__/file.js", "*/mock/*"},
		{"vendor/lib.go", "*/vendor/*"},
		{"node_modules/pkg/index.js", "*/node_modules/*"},
		{"example/config.env", "*/example/*"},
		{"examples/setup.js", "*/example/*"},
		{"fixtures/data.json", "*/example/*"},
		{"Makefile", "*"},
		{".env", "*.env"},
		{"config.yaml", "*.yaml"},
	}
	for _, tt := range tests {
		got := ExtractFilePattern(tt.input)
		if got != tt.want {
			t.Errorf("ExtractFilePattern(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestClassifyTier(t *testing.T) {
	tests := []struct {
		sampleCount int
		want        Tier
	}{
		{0, TierExperimental},
		{5, TierExperimental},
		{9, TierExperimental},
		{10, TierLearning},
		{25, TierLearning},
		{49, TierLearning},
		{50, TierMature},
		{100, TierMature},
		{199, TierMature},
		{200, TierTrusted},
		{500, TierTrusted},
	}
	for _, tt := range tests {
		got := ClassifyTier(tt.sampleCount)
		if got != tt.want {
			t.Errorf("ClassifyTier(%d) = %v, want %v", tt.sampleCount, got, tt.want)
		}
	}
}

func TestTierLabel(t *testing.T) {
	if TierExperimental.Label() != "Experimental" {
		t.Errorf("got %q", TierExperimental.Label())
	}
	if TierLearning.Label() != "Learning" {
		t.Errorf("got %q", TierLearning.Label())
	}
	if TierMature.Label() != "Mature" {
		t.Errorf("got %q", TierMature.Label())
	}
	if TierTrusted.Label() != "Trusted" {
		t.Errorf("got %q", TierTrusted.Label())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adaptive/ -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement adaptive.go (types + file pattern + tier)**

```go
// internal/adaptive/adaptive.go
package adaptive

import (
	"math"
	"path/filepath"
	"strings"
	"time"
)

// Tier represents the learning maturity of a (rule, file_pattern) combo.
type Tier int

const (
	TierExperimental Tier = 0
	TierLearning     Tier = 1
	TierMature       Tier = 2
	TierTrusted      Tier = 3
)

func (t Tier) Label() string {
	switch t {
	case TierExperimental:
		return "Experimental"
	case TierLearning:
		return "Learning"
	case TierMature:
		return "Mature"
	case TierTrusted:
		return "Trusted"
	default:
		return "Unknown"
	}
}

func ClassifyTier(sampleCount int) Tier {
	switch {
	case sampleCount >= 200:
		return TierTrusted
	case sampleCount >= 50:
		return TierMature
	case sampleCount >= 10:
		return TierLearning
	default:
		return TierExperimental
	}
}

// Verdict represents a single user verdict on a finding.
type Verdict struct {
	Fingerprint string
	Verdict     string // "tp" or "fp"
	CreatedAt   time.Time
}

// LearnedWeight stores the precomputed learning data for a (rule, file_pattern) combo.
type LearnedWeight struct {
	RuleName    string
	FilePattern string
	TPWeighted  float64
	FPWeighted  float64
	SampleCount int
	Tier        Tier
	Modifier    float64
}

// ExtractFilePattern reduces a file path to a canonical pattern for learning.
func ExtractFilePattern(filePath string) string {
	lower := strings.ToLower(filePath)
	parts := strings.Split(lower, "/")

	// Check directory-based patterns (last 2 path components)
	for i := 0; i < len(parts)-1; i++ {
		dir := parts[i]
		if dir == "test" || dir == "tests" || dir == "__tests__" {
			return "*/test/*"
		}
		if dir == "mock" || dir == "__mocks__" {
			return "*/mock/*"
		}
		if dir == "vendor" || dir == "node_modules" {
			return "*/vendor/*"
		}
		if dir == "example" || dir == "examples" || dir == "fixtures" {
			return "*/example/*"
		}
	}

	// Extension-based pattern
	ext := filepath.Ext(filePath)
	if ext != "" {
		return "*" + ext
	}
	return "*"
}

// DecayHalfLife is the half-life for exponential decay of verdict weights.
const DecayHalfLife = 90.0 // days

// ComputeWeightedStats returns decay-weighted FP and TP counts and total sample count.
func ComputeWeightedStats(verdicts []Verdict) (weightedFP, weightedTP float64, sampleCount int) {
	now := time.Now()
	for _, v := range verdicts {
		ageDays := now.Sub(v.CreatedAt).Hours() / 24.0
		w := math.Exp(-ageDays / DecayHalfLife)
		if v.Verdict == "fp" {
			weightedFP += w
		} else {
			weightedTP += w
		}
		sampleCount++
	}
	return
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adaptive/ -run "TestExtractFilePattern|TestClassifyTier|TestTierLabel" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adaptive/adaptive.go internal/adaptive/adaptive_test.go
git commit -m "feat(adaptive): add file pattern extraction and tier classification"
```

---

## Task 3: Modifier Computation — Bayesian Smoothing, Ramp-Up, Cap, Clamp

**Files:**
- Modify: `internal/adaptive/adaptive.go`
- Modify: `internal/adaptive/adaptive_test.go`

- [ ] **Step 1: Write failing tests for modifier computation**

```go
// Add to internal/adaptive/adaptive_test.go

func TestComputeModifier_BayesianSmoothing(t *testing.T) {
	// 1 FP, 0 TP — raw ratio would be 1.0, smoothed should be ~0.55
	verdicts := []Verdict{
		{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)},
	}
	mod := ComputeModifier("generic_api_key", verdicts)
	// smoothed = (0.99 + 5) / (0.99 + 0 + 10) ≈ 0.546
	// base modifier = (1 - 2*0.546) * 40 ≈ -3.7
	// ramp: 1/20 = 0.05 → -3.7 * 0.05 ≈ -0.18 → clamp → 0
	if mod > 1 || mod < -1 {
		t.Errorf("1 FP, 0 TP: modifier should be near 0 due to smoothing + ramp, got %f", mod)
	}
}

func TestComputeModifier_AllFP_Heavy(t *testing.T) {
	// 100 FP, 0 TP — heavy FP, mature sample
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("generic_api_key", verdicts)
	// smoothed = (99.9 + 5) / (99.9 + 0 + 10) ≈ 0.954
	// base = (1 - 2*0.954) * 40 ≈ -36.3
	// ramp: 100/20 = 1.0 (no ramp)
	// cap: generic → full range
	// result ≈ -36
	if mod > -30 {
		t.Errorf("100 FP, 0 TP: modifier should be heavily negative, got %f", mod)
	}
}

func TestComputeModifier_AllTP_Boost(t *testing.T) {
	// 0 FP, 100 TP — reliable rule
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "tp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("aws_access_key", verdicts)
	// smoothed = (0 + 5) / (0 + 99.9 + 10) ≈ 0.045
	// base = (1 - 2*0.045) * 40 ≈ 36.4
	if mod < 30 {
		t.Errorf("100 TP, 0 FP: modifier should be heavily positive, got %f", mod)
	}
}

func TestComputeModifier_MinimumEvidenceRampUp(t *testing.T) {
	// 5 FP, 0 TP — should be heavily ramped down
	verdicts := make([]Verdict, 5)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod5 := ComputeModifier("generic_api_key", verdicts)

	// 20 FP, 0 TP — no ramp
	verdicts20 := make([]Verdict, 20)
	for i := range verdicts20 {
		verdicts20[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod20 := ComputeModifier("generic_api_key", verdicts20)

	// mod5 should be less negative than mod20 (ramp reduces magnitude)
	if mod5 < mod20 {
		t.Errorf("ramp-up failed: mod5=%f should be less negative than mod20=%f", mod5, mod20)
	}
}

func TestComputeModifier_HighCertaintyCap(t *testing.T) {
	// aws_access_key with many FPs — should be capped at -10
	verdicts := make([]Verdict, 100)
	for i := range verdicts {
		verdicts[i] = Verdict{Verdict: "fp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("aws_access_key", verdicts)
	if mod < -10 {
		t.Errorf("high-certainty rule capped at -10, got %f", mod)
	}
}

func TestComputeModifier_Empty(t *testing.T) {
	mod := ComputeModifier("any_rule", nil)
	if mod != 0 {
		t.Errorf("empty verdicts should return 0, got %f", mod)
	}
}

func TestComputeModifier_Clamp(t *testing.T) {
	// Verify clamp boundaries
	verdicts100tp := make([]Verdict, 500)
	for i := range verdicts100tp {
		verdicts100tp[i] = Verdict{Verdict: "tp", CreatedAt: time.Now().Add(-1 * time.Hour)}
	}
	mod := ComputeModifier("generic_api_key", verdicts100tp)
	if mod > 40 {
		t.Errorf("modifier should clamp at 40, got %f", mod)
	}
	if mod < -40 {
		t.Errorf("modifier should clamp at -40, got %f", mod)
	}
}

func TestHighCertaintyRules(t *testing.T) {
	rules := []string{"aws_access_key", "github_pat", "stripe_live_key", "private_key"}
	for _, r := range rules {
		if !isHighCertainty(r) {
			t.Errorf("expected %s to be high-certainty", r)
		}
	}
	if isHighCertainty("generic_api_key") {
		t.Error("generic_api_key should not be high-certainty")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adaptive/ -run "TestComputeModifier|TestHighCertainty" -v`
Expected: FAIL — `ComputeModifier` and `isHighCertainty` not defined

- [ ] **Step 3: Implement modifier computation**

Add to `internal/adaptive/adaptive.go`:

```go
// High-certainty rules that should never be heavily penalized.
var highCertaintyRules = map[string]bool{
	"aws_access_key":     true,
	"github_pat":         true,
	"stripe_live_key":    true,
	"private_key":        true,
	"aws_secret_key":     true,
	"github_oauth_token": true,
	"stripe_restricted":  true,
}

func isHighCertainty(ruleName string) bool {
	return highCertaintyRules[ruleName]
}

func clamp(low, high, val float64) float64 {
	if val < low {
		return low
	}
	if val > high {
		return high
	}
	return val
}

// ComputeModifier computes the adaptive confidence modifier for a rule
// given its verdict history. Uses Bayesian smoothing, minimum evidence
// ramp-up, per-rule caps, and clamping.
func ComputeModifier(ruleName string, verdicts []Verdict) float64 {
	if len(verdicts) == 0 {
		return 0
	}

	weightedFP, weightedTP, sampleCount := ComputeWeightedStats(verdicts)

	// Step 1: Bayesian smoothing (prior: 5 TP + 5 FP)
	smoothedFPRatio := (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)

	// Step 2: Base modifier
	modifier := (1 - 2*smoothedFPRatio) * 40

	// Step 3: Minimum evidence ramp-up
	if sampleCount < 20 {
		modifier *= float64(sampleCount) / 20.0
	}

	// Step 4: Per-rule cap
	if isHighCertainty(ruleName) && modifier < -10 {
		modifier = -10
	}

	// Step 5: Clamp
	return clamp(-40, 40, modifier)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adaptive/ -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adaptive/adaptive.go internal/adaptive/adaptive_test.go
git commit -m "feat(adaptive): add modifier computation with Bayesian smoothing, ramp-up, cap"
```

---

## Task 4: LearnedWeight Store + Recompute

**Files:**
- Modify: `internal/adaptive/adaptive.go`
- Modify: `internal/adaptive/adaptive_test.go`
- Modify: `internal/correlator/cache.go`

- [ ] **Step 1: Write failing tests for recompute + lookup**

```go
// Add to internal/adaptive/adaptive_test.go

func TestLearnedWeightStore_Lookup(t *testing.T) {
	store := NewLearnedWeightStore()
	store.Set("generic_api_key", "*.test.js", 10, 80, 90)
	w := store.Get("generic_api_key", "*.test.js")
	if w == nil {
		t.Fatal("expected weight, got nil")
	}
	if w.Tier != TierMature {
		t.Errorf("expected Mature tier, got %v", w.Tier)
	}
}

func TestLearnedWeightStore_Default(t *testing.T) {
	store := NewLearnedWeightStore()
	w := store.Get("unknown_rule", "*.js")
	if w != nil {
		t.Error("expected nil for unknown rule")
	}
}
```

```go
// Add to internal/correlator/cache_test.go

func TestCacheRecomputeWeights(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Record some findings
	fp1 := Fingerprint("rule_a", "secret1", "test.js")
	fp2 := Fingerprint("rule_a", "secret2", "test.js")
	c.Record(fp1)
	c.Record(fp2)

	// Add verdicts
	c.Verdict(fp1, "fp")
	c.Verdict(fp1, "fp")
	c.Verdict(fp2, "tp")

	// Recompute
	err = c.RecomputeWeights()
	if err != nil {
		t.Fatal(err)
	}

	// Verify learned_weights populated
	var count int
	c.db.QueryRow("SELECT COUNT(*) FROM learned_weights").Scan(&count)
	if count == 0 {
		t.Error("expected learned_weights to have rows after recompute")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adaptive/ -run "TestLearnedWeightStore" -v` and `go test ./internal/correlator/ -run "TestCacheRecomputeWeights" -v`
Expected: FAIL

- [ ] **Step 3: Implement LearnedWeightStore**

Add to `internal/adaptive/adaptive.go`:

```go
// LearnedWeightStore is an in-memory store of learned weights.
type LearnedWeightStore struct {
	weights map[string]*LearnedWeight // key: "ruleName|filePattern"
}

func NewLearnedWeightStore() *LearnedWeightStore {
	return &LearnedWeightStore{weights: make(map[string]*LearnedWeight)}
}

func (s *LearnedWeightStore) Set(ruleName, filePattern string, tpWeighted, fpWeighted float64, sampleCount int) {
	key := ruleName + "|" + filePattern
	modifier := ComputeModifierFromStats(ruleName, fpWeighted, tpWeighted, sampleCount)
	s.weights[key] = &LearnedWeight{
		RuleName:    ruleName,
		FilePattern: filePattern,
		TPWeighted:  tpWeighted,
		FPWeighted:  fpWeighted,
		SampleCount: sampleCount,
		Tier:        ClassifyTier(sampleCount),
		Modifier:    modifier,
	}
}

func (s *LearnedWeightStore) Get(ruleName, filePattern string) *LearnedWeight {
	key := ruleName + "|" + filePattern
	return s.weights[key]
}

// ComputeModifierFromStats computes a modifier from pre-aggregated stats.
func ComputeModifierFromStats(ruleName string, weightedFP, weightedTP float64, sampleCount int) float64 {
	if sampleCount == 0 {
		return 0
	}
	smoothedFPRatio := (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)
	modifier := (1 - 2*smoothedFPRatio) * 40
	if sampleCount < 20 {
		modifier *= float64(sampleCount) / 20.0
	}
	if isHighCertainty(ruleName) && modifier < -10 {
		modifier = -10
	}
	return clamp(-40, 40, modifier)
}
```

- [ ] **Step 4: Implement RecomputeWeights in cache.go**

Add to `internal/correlator/cache.go`:

```go
// RecomputeWeights rebuilds the learned_weights table from verdicts + findings.
func (c *Cache) RecomputeWeights() error {
	rows, err := c.db.Query(`
		SELECT f.rule_name, f.file, v.verdict, v.created_at
		FROM verdicts v
		JOIN findings f ON v.fingerprint = f.fingerprint
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

	// Clear and rebuild learned_weights
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
			return fmt.Errorf("upsert learned weight: %w", err)
		}
	}
	return nil
}
```

Also add `LoadWeights` to cache.go:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/adaptive/ ./internal/correlator/ -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/adaptive/adaptive.go internal/adaptive/adaptive_test.go internal/correlator/cache.go internal/correlator/cache_test.go
git commit -m "feat(adaptive): add LearnedWeightStore, recompute, and load weights"
```

---

## Task 5: Verdict CLI Command

**Files:**
- Create: `cmd/verdict.go`
- Create: `cmd/verdict_test.go`
- Modify: `cmd/root.go`

- [ ] **Step 1: Write failing test for verdict command**

```go
// cmd/verdict_test.go
package cmd

import (
	"testing"
)

func TestVerdictRequiresCacheDB(t *testing.T) {
	// Running verdict without --cache-db should error
	// This tests that the flag is properly validated
}
```

- [ ] **Step 2: Implement cmd/verdict.go**

```go
// cmd/verdict.go
package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/RA000WL/syck/internal/correlator"
)

var verdictCacheDB string
var verdictStats bool

var verdictCmd = &cobra.Command{
	Use:   "verdict [fingerprint tp|fp ...]",
	Short: "Label findings as true positive or false positive for adaptive learning",
	Long: `Record verdicts on findings to train the adaptive confidence system.

Examples:
  syck verdict abc123 fp --cache-db scan.db
  syck verdict abc123 tp def456 fp --cache-db scan.db
  syck verdict --stats --cache-db scan.db`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if verdictCacheDB == "" {
			return fmt.Errorf("--cache-db is required")
		}

		cache, err := correlator.OpenCache(verdictCacheDB)
		if err != nil {
			return fmt.Errorf("open cache: %w", err)
		}
		defer cache.Close()

		if verdictStats {
			return printVerdictStats(cache)
		}

		if len(args) == 0 {
			return fmt.Errorf("provide fingerprint(s) and verdict(s), or use --stats")
		}
		if len(args)%2 != 0 {
			return fmt.Errorf("arguments must be pairs of fingerprint and verdict (tp/fp)")
		}

		for i := 0; i < len(args); i += 2 {
			fp := args[i]
			verdict := args[i+1]
			if verdict != "tp" && verdict != "fp" {
				return fmt.Errorf("invalid verdict %q for %s (must be tp or fp)", verdict, fp)
			}
			if err := cache.Verdict(fp, verdict); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}
			fmt.Printf("Recorded %s verdict for %s\n", verdict, fp)
		}

		// Recompute weights after recording verdicts
		if err := cache.RecomputeWeights(); err != nil {
			return fmt.Errorf("recompute weights: %w", err)
		}

		return nil
	},
}

func printVerdictStats(cache *correlator.Cache) error {
	rows, err := cache.GetWeightedStats()
	if err != nil {
		return fmt.Errorf("query stats: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Rule\tFile Pattern\tTP\tFP\tSmoothed\tAdj\tTier")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%.2f\t%+.0f\t%s\n",
			r.RuleName, r.FilePattern, r.TPCount, r.FPCount,
			r.SmoothedFPRatio, r.Modifier, r.TierLabel)
	}
	w.Flush()

	var totalVerdicts int
	cache.db.QueryRow("SELECT COUNT(*) FROM verdicts").Scan(&totalVerdicts)
	fmt.Printf("\nTotal verdicts: %d | Adaptive rules: %d\n", totalVerdicts, len(rows))
	return nil
}

func init() {
	verdictCmd.Flags().StringVar(&verdictCacheDB, "cache-db", "", "path to SQLite cache database")
	verdictCmd.Flags().BoolVar(&verdictStats, "stats", false, "show learning summary")
	rootCmd.AddCommand(verdictCmd)
}
```

- [ ] **Step 3: Add GetWeightedStats to cache.go**

```go
// WeightedStatRow is a row from the stats query.
type WeightedStatRow struct {
	RuleName       string
	FilePattern    string
	TPCount        int
	FPCount        int
	SmoothedFPRatio float64
	Modifier       float64
	TierLabel      string
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
		if err := rows.Scan(&r.RuleName, &r.FilePattern, &r.TPCount, &r.FPCount, &r.TierCount, &tier, &r.Modifier); err != nil {
			return nil, err
		}
		r.TierLabel = adaptive.Tier(tier).Label()
		r.SmoothedFPRatio = (float64(r.FPCount) + 5.0) / (float64(r.FPCount) + float64(r.TPCount) + 10.0)
		results = append(results, r)
	}
	return results, nil
}
```

- [ ] **Step 4: Run tests and verify build**

Run: `go build ./...`
Expected: PASS

Run: `go test ./cmd/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/verdict.go cmd/verdict_test.go cmd/root.go internal/correlator/cache.go
git commit -m "feat(adaptive): add verdict CLI command with stats"
```

---

## Task 6: Finding Struct + Confidence Scorer Extension

**Files:**
- Modify: `internal/finding/finding.go`
- Modify: `internal/confidence/confidence.go`

- [ ] **Step 1: Add fields to Finding struct**

Add to `internal/finding/finding.go` after `DecodedValuePreview`:

```go
type Finding struct {
	// ... existing fields ...
	DecodedValuePreview string
	AdaptiveModifier    int    `json:"adaptive_modifier,omitempty"`
	LearningTier        string `json:"learning_tier,omitempty"`
}
```

- [ ] **Step 2: Add ScoreWithAdaptive to confidence.go**

Add to `internal/confidence/confidence.go`:

```go
// ScoreWithAdaptive computes confidence and applies an adaptive modifier.
func (s *Scorer) ScoreWithAdaptive(sig Signals, adaptiveMod int) int {
	base := s.Score(sig)
	adjusted := base + adaptiveMod
	if adjusted < 0 {
		adjusted = 0
	}
	if adjusted > 120 {
		adjusted = 120
	}
	return adjusted
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/finding/finding.go internal/confidence/confidence.go
git commit -m "feat(adaptive): add AdaptiveModifier/LearningTier to Finding, ScoreWithAdaptive to scorer"
```

---

## Task 7: Scanner Config + Wiring

**Files:**
- Modify: `internal/scanner/scanner.go`
- Modify: `internal/scanner/scan.go`
- Modify: `cmd/scan.go`

- [ ] **Step 1: Add Adaptive flag to Config**

Add to `internal/scanner/scanner.go`:

```go
type Config struct {
	// ... existing fields ...
	CacheDB           string
	Adaptive          bool // enable adaptive confidence learning
	AdaptiveWeights   *adaptive.LearnedWeightStore // loaded weights (nil if not adaptive)
}
```

- [ ] **Step 2: Add import for adaptive package**

Add to `internal/scanner/scanner.go` imports:

```go
import (
	"regexp"

	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)
```

- [ ] **Step 3: Wire adaptive weights into scan.go**

In `internal/scanner/scan.go`, find the CacheDB loading block (around line 184) and extend it:

```go
if cfg.CacheDB != "" {
	cache, err := correlator.OpenCache(cfg.CacheDB)
	if err == nil {
		for i := range allFindings {
			fp := correlator.Fingerprint(allFindings[i].RuleName, allFindings[i].Secret, allFindings[i].File)
			isNew, _ := cache.Record(fp)
			if isNew {
				allFindings[i].IsNew = true
			}
		}
		// New: apply adaptive modifiers
		if cfg.Adaptive && cfg.AdaptiveWeights != nil {
			for i := range allFindings {
				fp := adaptive.ExtractFilePattern(allFindings[i].File)
				w := cfg.AdaptiveWeights.Get(allFindings[i].RuleName, fp)
				if w != nil {
					allFindings[i].AdaptiveModifier = int(w.Modifier)
					allFindings[i].LearningTier = w.Tier.Label()
				}
			}
		}
		cache.Close()
	}
}
```

- [ ] **Step 4: Load weights in ScanPaths (start of scan)**

In `internal/scanner/scan.go`, find `ScanPaths` function. Add at the start, after config validation:

```go
// Load adaptive weights if enabled
if cfg.Adaptive && cfg.CacheDB != "" {
	cache, err := correlator.OpenCache(cfg.CacheDB)
	if err == nil {
		weights, err := cache.LoadWeights()
		if err == nil {
			cfg.AdaptiveWeights = weights
		}
		cache.Close()
	}
}
```

- [ ] **Step 5: Add --adaptive flag to cmd/scan.go**

In `cmd/scan.go`, add variable and flag:

```go
var adaptive bool

// In scanCmd init or flag registration section:
scanCmd.Flags().BoolVar(&adaptive, "adaptive", false, "enable adaptive confidence learning (requires --cache-db)")
```

In `runScan`, add to Config construction:

```go
Config: scanner.Config{
	// ... existing fields ...
	CacheDB:  cacheDB,
	Adaptive: adaptive,
},
```

- [ ] **Step 6: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/scanner/scanner.go internal/scanner/scan.go cmd/scan.go
git commit -m "feat(adaptive): wire adaptive weights into scan pipeline"
```

---

## Task 8: Output Format Updates (text, JSON, SARIF, markdown, CSV, HTML)

**Files:**
- Modify: `internal/formatters/text.go`
- Modify: `internal/formatters/json.go`
- Modify: `internal/formatters/sarif.go`
- Modify: `internal/formatters/markdown.go`
- Modify: `internal/formatters/csv.go`
- Modify: `internal/formatters/html.go`

- [ ] **Step 1: Update text.go**

In `internal/formatters/text.go`, find the output line (around line 90) and add adaptive info:

```go
// After the verStr line:
adaptiveStr := ""
if f.AdaptiveModifier != 0 {
	adaptiveStr = fmt.Sprintf(" adaptive=%+d [%s]", f.AdaptiveModifier, f.LearningTier)
}

// Include adaptiveStr in the output line (both color and no-color paths)
```

- [ ] **Step 2: Update json.go**

In `internal/formatters/json.go`, add fields to `jsonFinding`:

```go
type jsonFinding struct {
	// ... existing fields ...
	AdaptiveModifier int    `json:"adaptive_modifier,omitempty"`
	LearningTier     string `json:"learning_tier,omitempty"`
}
```

In the `Format` method, set them:

```go
out.Findings[i] = jsonFinding{
	// ... existing fields ...
	AdaptiveModifier: f.AdaptiveModifier,
	LearningTier:     f.LearningTier,
}
```

- [ ] **Step 3: Update sarif.go**

In `internal/formatters/sarif.go`, add to the properties map of each result:

```go
if f.AdaptiveModifier != 0 {
	props["adaptive_modifier"] = f.AdaptiveModifier
	props["learning_tier"] = f.LearningTier
}
```

- [ ] **Step 4: Update markdown.go, csv.go, html.go**

Add `Adapt` and `Tier` columns to each formatter's output, following the same pattern as existing columns.

- [ ] **Step 5: Verify build**

Run: `go build ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/formatters/
git commit -m "feat(adaptive): add adaptive modifier + tier to all output formats"
```

---

## Task 9: Integration Tests

**Files:**
- Modify: `internal/adaptive/adaptive_test.go`
- Modify: `internal/correlator/cache_test.go`

- [ ] **Step 1: Write full flow integration test**

```go
// Add to internal/correlator/cache_test.go

func TestAdaptiveFullFlow(t *testing.T) {
	db := t.TempDir() + "/test.db"
	c, err := OpenCache(db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. Record findings
	fp := Fingerprint("generic_api_key", "sk_test123", "test/config.js")
	c.Record(fp)

	// 2. Verdict: FP
	c.Verdict(fp, "fp")

	// 3. Recompute
	c.RecomputeWeights()

	// 4. Load weights
	store, err := c.LoadWeights()
	if err != nil {
		t.Fatal(err)
	}
	w := store.Get("generic_api_key", "*/test/*")
	if w == nil {
		t.Fatal("expected learned weight for generic_api_key in test")
	}

	// 5. Verify modifier is negative (1 FP → smoothed ≈ 0.55 → modifier ≈ -2.2 at 1 sample)
	if w.Modifier >= 0 {
		t.Errorf("expected negative modifier for FP, got %f", w.Modifier)
	}
	if w.Tier != TierExperimental {
		t.Errorf("expected Experimental tier at 1 sample, got %v", w.Tier)
	}
}
```

- [ ] **Step 2: Run all tests**

Run: `go test -race ./...`
Expected: ALL PASS

- [ ] **Step 3: Run go vet**

Run: `go vet ./...`
Expected: PASS

- [ ] **Step 4: Run gofmt check**

Run: `gofmt -l .`
Expected: No output (all formatted)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "test(adaptive): add integration tests for full adaptive flow"
```

---

## Task 10: Documentation Updates

**Files:**
- Modify: `ARCHITECTURE.md`
- Modify: `README.md`

- [ ] **Step 1: Update ARCHITECTURE.md**

Add adaptive learning section to the package map and data flow diagram.

- [ ] **Step 2: Update README.md**

Add adaptive learning to the Features list and add a usage example:

```bash
# Scan with adaptive learning
syck scan . --cache-db scan.db --adaptive

# Label findings
syck verdict <fingerprint> fp --cache-db scan.db

# View learning stats
syck verdict --stats --cache-db scan.db
```

- [ ] **Step 3: Final verification**

Run: `go test -race ./... && go vet ./... && gofmt -l .`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add ARCHITECTURE.md README.md
git commit -m "docs: add adaptive learning to ARCHITECTURE.md and README.md"
```
