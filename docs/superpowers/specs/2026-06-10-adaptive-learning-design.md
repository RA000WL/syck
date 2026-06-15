# Adaptive Learning Design Spec

> Version: 1.1 | Date: 2026-06-10 | Status: Draft

## Overview

Add adaptive confidence learning to syck. Users label findings as TP/FP via a CLI verdict command. The scanner learns from this feedback over time, adjusting confidence scores for findings that historically produce false positives or true positives.

**Key decisions:**
- Triage method: CLI verdict command (`syck verdict <fingerprint> tp|fp`)
- Learning scope: Global (shared across all projects using the same DB)
- Learning depth: Confidence adjustment only (no rule generation)
- Decay: Exponential decay with 90-day half-life (recent verdicts matter more)

## Goals

1. Reduce false positive fatigue — rules that produce FPs get penalized automatically
2. Reward reliable rules — rules with high TP rates get confidence boosts
3. Context-aware — same rule in `test/` vs `src/` learns independently
4. Transparent — `AdaptiveModifier` field on every finding shows what changed
5. Backwards compatible — `--cache-db` without `--adaptive` behaves identically to today

## Non-Goals

- Automatic rule generation from confirmed TPs (future phase)
- Team-shared learned weights (each DB is independent)
- Real-time learning during scan (weights recomputed at scan start or on verdict)
- Verdict reasons (future phase — see Future Work)

---

## Schema Changes

### Existing Table (unchanged)

```sql
CREATE TABLE findings (
    fingerprint TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
```

### New: Verdict Log

```sql
CREATE TABLE verdicts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    verdict     TEXT NOT NULL CHECK(verdict IN ('tp', 'fp')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint)
);
```

- Append-only (never delete, audit trail)
- One row per user verdict action
- `fingerprint` links to `findings` table

### New: Learned Weights (Materialized Cache)

```sql
CREATE TABLE learned_weights (
    rule_name       TEXT NOT NULL,
    file_pattern    TEXT NOT NULL,
    tp_weighted     REAL NOT NULL,  -- decay-weighted TP count
    fp_weighted     REAL NOT NULL,  -- decay-weighted FP count
    sample_count    INTEGER NOT NULL,
    tier            INTEGER NOT NULL,  -- 0=Experimental, 1=Learning, 2=Mature, 3=Trusted
    modifier        REAL NOT NULL,     -- final computed modifier (-40 to +40)
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (rule_name, file_pattern)
);
```

- Recomputed on `syck scan --adaptive` start and on each `syck verdict` call
- `file_pattern` is derived from the finding's file path (see File Pattern Extraction)

---

## File Pattern Extraction

The finding's file path is reduced to a canonical pattern for the learned_weights lookup:

```go
func ExtractFilePattern(filePath string) string {
    // Priority order:
    // 1. If in test dir    → "*/test/*" or "*/tests/*" or "*/__tests__/*"
    // 2. If in mock dir    → "*/mock/*" or "*/__mocks__/*"
    // 3. If in vendor      → "*/vendor/*" or "*/node_modules/*"
    // 4. If in example dir → "*/example/*" or "*/examples/*" or "*/fixtures/*"
    // 5. Otherwise         → extension pattern "*.ext" (e.g. "*.js", "*.env")
    // 6. No extension      → "*"
}
```

This ensures the same rule learns independently across different file contexts.

---

## Confidence Adjustment

### Learning Tiers

Each (rule_name, file_pattern) combo is classified into a tier based on sample count:

| Samples | Tier | Label | Meaning |
|---------|------|-------|---------|
| 0-9 | 0 | Experimental | Insufficient data, minimal adjustment |
| 10-49 | 1 | Learning | Early signals, moderate adjustment |
| 50-199 | 2 | Mature | Reliable patterns, full adjustment |
| 200+ | 3 | Trusted | High confidence in the learned signal |

Tier is stored in `learned_weights` and displayed in output for transparency.

### Robustness Mechanisms

#### 1. Bayesian Smoothing (Small Sample Bias)

Raw FP ratios are unstable with few verdicts. One mistaken verdict on a new rule could tank it to -40.

**Solution:** Bayesian smoothing with a prior of 5 TP + 5 FP:

```
smoothedFpRatio = (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)
```

Equivalent to assuming 5 TP and 5 FP before seeing any real data.

| Data | Raw Ratio | Smoothed Ratio |
|------|-----------|----------------|
| 1 FP, 0 TP | 1.00 | 0.55 |
| 2 FP, 0 TP | 1.00 | 0.58 |
| 10 FP, 0 TP | 1.00 | 0.75 |
| 100 FP, 0 TP | 1.00 | 0.95 |
| 5 FP, 5 TP | 0.50 | 0.50 |
| 1 FP, 10 TP | 0.09 | 0.33 |

The smoothing effect diminishes as sample count grows. At 200+ verdicts, the raw ratio dominates.

#### 2. Minimum Evidence Ramp-Up (Generic Rules Learning Too Fast)

A rule with 1 FP and 0 TP shouldn't get the full -40 penalty. Ramp up the modifier linearly:

```
if sampleCount < 20 {
    modifier *= float64(sampleCount) / 20.0
}
```

| Samples | Effective Modifier |
|---------|-------------------|
| 1 | 5% of full modifier |
| 5 | 25% |
| 10 | 50% |
| 15 | 75% |
| 20+ | 100% |

This prevents a single mistaken verdict from heavily penalizing a rule.

#### 3. Per-Rule Caps (High-Certainty Rules)

Some rules have extremely low FP rates by design. Even if users mark some as FP, the penalty should be bounded.

**High-certainty rules** (capped at -10 max negative modifier):
- `aws_access_key`
- `github_pat`
- `stripe_live_key`
- `private_key`
- Any rule with tag `high-certainty`

**Generic rules** (full range -40 to +40):
- `generic_api_key`
- `password_assignment`
- `token_variable`
- All others

```go
func cappedModifier(ruleName string, rawModifier float64) float64 {
    if isHighCertainty(ruleName) && rawModifier < -10 {
        return -10
    }
    return rawModifier
}
```

### Modifier Formula (Complete)

```
// Step 1: Bayesian smoothing
smoothedFpRatio = (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)

// Step 2: Base modifier
modifier = (1 - 2 * smoothedFpRatio) * 40

// Step 3: Minimum evidence ramp-up
if sampleCount < 20 {
    modifier *= float64(sampleCount) / 20.0
}

// Step 4: Per-rule cap
modifier = cappedModifier(ruleName, modifier)

// Step 5: Clamp
modifier = clamp(-40, +40, modifier)
```

| Smoothed FP Ratio | Raw Modifier | At 5 samples | At 10 samples | At 20+ samples |
|-------------------|-------------|-------------|---------------|----------------|
| 0.95 | -36 | -9 | -18 | -36 |
| 0.75 | -20 | -5 | -10 | -20 |
| 0.55 | -4 | -1 | -2 | -4 |
| 0.50 | 0 | 0 | 0 | 0 |
| 0.30 | +16 | +4 | +8 | +16 |
| 0.10 | +32 | +8 | +16 | +32 |
| 0.05 | +36 | +9 | +18 | +36 |

### Decay Weight

```
weight = exp(-age_days / 90.0)
```

| Age | Weight |
|-----|--------|
| 7 days | 0.93 |
| 30 days | 0.72 |
| 90 days | 0.37 |
| 180 days | 0.14 |
| 365 days | 0.02 |

Recent verdicts dominate. Old verdicts fade naturally.

### Weighted FP Ratio Computation

```go
func ComputeWeightedFPStats(verdicts []Verdict) (weightedFP, weightedTP float64, sampleCount int) {
    now := time.Now()
    for _, v := range verdicts {
        ageDays := now.Sub(v.CreatedAt).Hours() / 24.0
        w := math.Exp(-ageDays / 90.0)
        if v.Verdict == "fp" {
            weightedFP += w
        } else {
            weightedTP += w
        }
        sampleCount++
    }
    return
}

func ComputeModifier(ruleName string, verdicts []Verdict) float64 {
    if len(verdicts) == 0 {
        return 0  // no data, no adjustment
    }
    
    weightedFP, weightedTP, sampleCount := ComputeWeightedFPStats(verdicts)
    
    // Step 1: Bayesian smoothing
    smoothedFpRatio := (weightedFP + 5.0) / (weightedFP + weightedTP + 10.0)
    
    // Step 2: Base modifier
    modifier := (1 - 2*smoothedFpRatio) * 40
    
    // Step 3: Minimum evidence ramp-up
    if sampleCount < 20 {
        modifier *= float64(sampleCount) / 20.0
    }
    
    // Step 4: Per-rule cap
    modifier = cappedModifier(ruleName, modifier)
    
    // Step 5: Clamp
    return clamp(-40, 40, modifier)
}
```

### Integration in Scoring

```go
func (s *Scorer) ScoreWithAdaptive(sig Signals, weights *LearnedWeights) int {
    base := s.Score(sig)
    if weights == nil {
        return base
    }
    modifier := weights.Modifier(sig.RuleName, sig.FilePattern)
    adjusted := base + modifier
    return clamp(0, 120, adjusted)
}
```

### Fixed Example (Stats Output)

```
Rule                        | File Pattern   | TP  | FP  | Smoothed | Adj | Tier
generic_api_key             | *.test.js      |  12 |  88 | 0.84     | -27 | Mature
aws_access_key              | *              |  98 |   2 | 0.07     | +33 | Trusted
stripe_secret_key           | *.env          |  45 |   5 | 0.18     | +14 | Mature
new_rule                    | *.json         |   1 |   2 | 0.53     | -1  | Experimental

Total verdicts: 250 | Adaptive rules: 4
```

---

## CLI: verdict Command

### Usage

```bash
# Label a finding as false positive
syck verdict <fingerprint> fp --cache-db scan.db

# Label a finding as true positive
syck verdict <fingerprint> tp --cache-db scan.db

# Batch: label multiple at once
syck verdict abc123 fp def456 tp ghi789 fp --cache-db scan.db

# List verdicts with stats
syck verdict --stats --cache-db scan.db
```

### Flags

| Flag | Description |
|------|-------------|
| `--cache-db` | Path to SQLite cache database (required) |
| `--stats` | Show learning summary table |

### Behavior

1. Requires `--cache-db` (same DB as the scan)
2. Validates fingerprint exists in `findings` table before accepting
3. Stores verdict with timestamp in `verdicts` table
4. Recomputes `learned_weights` for affected (rule, file_pattern) combos
5. Prints confirmation

### Output

**Verdict recorded:**
```
Recorded FP verdict for abc123 (generic_api_key in test/config.js)
```

**Stats output (`syck verdict --stats`):**
```
Rule                        | File Pattern   | TP  | FP  | Smoothed | Adj  | Tier
generic_api_key             | *.test.js      |  12 |  88 | 0.84     | -27  | Mature
aws_access_key              | *              |  98 |   2 | 0.07     | +33  | Trusted
stripe_secret_key           | *.env          |  45 |   5 | 0.18     | +14  | Mature
new_rule                    | *.json         |   1 |   2 | 0.53     | -1   | Experimental

Total verdicts: 250 | Adaptive rules: 4
```

---

## CLI: scan Command Additions

### New Flags

| Flag | Description |
|------|-------------|
| `--adaptive` | Enable adaptive confidence learning (requires --cache-db) |

### Behavior When --adaptive Is Set

1. Open cache DB (existing behavior)
2. **New:** Load `learned_weights` into memory
3. Scan files (existing pipeline)
4. **New:** For each finding:
   - Compute base confidence (existing)
   - Extract file_pattern from file path
   - Look up learned modifier from loaded weights
   - Apply modifier, clamp to [0, 120]
   - Set `Finding.AdaptiveModifier = modifier`
5. Record findings in cache (existing)
6. Output results (existing)

### Behavior Without --adaptive

Identical to current behavior. No schema changes affect existing scans.

---

## Finding Struct Extension

```go
type Finding struct {
    // ... existing fields ...
    AdaptiveModifier int    `json:"adaptive_modifier,omitempty"` // -40 to +40, 0 if no adjustment
    LearningTier      string `json:"learning_tier,omitempty"`     // Experimental/Learning/Mature/Trusted
}
```

- `AdaptiveModifier` omitted from JSON output when 0 (no adjustment applied)
- `LearningTier` omitted when empty (no learned data)
- Displayed in text output when non-zero
- Shows transparency: users can see exactly what the learning changed and how much data it's based on

---

## Recompute Learned Weights

Triggered on:
1. `syck scan --adaptive` start (before scanning)
2. `syck verdict <fingerprint> tp|fp` (after recording verdict)

Algorithm:
```sql
-- For each (rule_name, file_pattern) combo with verdicts:
SELECT
    f.rule_name,
    ExtractFilePattern(f.file) as file_pattern,
    v.verdict,
    v.created_at
FROM verdicts v
JOIN findings f ON v.fingerprint = f.fingerprint;
```

Then in Go:
1. Group verdicts by (rule_name, file_pattern)
2. Compute weighted FP/TP stats with decay for each group
3. Apply Bayesian smoothing, ramp-up, per-rule cap
4. Compute tier from sample count
5. UPSERT into `learned_weights` table (tp_weighted, fp_weighted, sample_count, tier, modifier)

---

## Output Format Changes

### Text Format

```
[HIGH]  [generic_api_key]  test/config.js:42:18  entropy=4.81  adaptive=-27 [Mature]
       secret : sk_xxxxxxxxxxxxxxxx
       context: const apiKey = "sk_xxxxxxxxxxxxxxxx";
```

The `adaptive=-27` shows the learned modifier. `[Mature]` shows the learning tier. Both omitted when no adjustment.

### JSON Format

```json
{
    "rule": "generic_api_key",
    "file": "test/config.js",
    "confidence": 33,
    "confidence_band": "MEDIUM",
    "adaptive_modifier": -27,
    "learning_tier": "Mature"
}
```

### Other Formats

SARIF: `adaptive_modifier` and `learning_tier` in `properties` object
Markdown/CSV/HTML: `Adapt` and `Tier` columns (omitted when no adjustment)

---

## Testing Strategy

### Unit Tests

1. **Schema migration** — existing DB without new tables works unchanged
2. **Verdict recording** — insert, validate fingerprint exists, duplicate handling
3. **Bayesian smoothing** — correct computation with prior, approaches raw ratio at scale
4. **Minimum evidence ramp-up** — modifier scales linearly 0-20 samples
5. **Per-rule cap** — high-certainty rules capped at -10, generic rules full range
6. **Modifier formula** — complete pipeline: smoothing → ramp → cap → clamp
7. **File pattern extraction** — test/mock/vendor/extension paths
8. **Tier classification** — correct tier for each sample count bracket
9. **Decay weight** — exponential decay correctness
10. **Scorer with adaptive** — base score + modifier, clamp, nil weights
11. **Recompute weights** — multiple verdicts, correct grouping, correct tier assignment
12. **Stats output** — formatting, empty state, tier display

### Integration Tests

1. **Full flow** — scan → verdict → scan with --adaptive → verify modifier applied
2. **Backwards compat** — scan without --adaptive → identical to current behavior
3. **Multiple scans** — scan → verdict → scan → verdict → verify decay affects results

### Test Fixtures

- `testdata/cache_empty.db` — fresh DB
- `testdata/cache_with_verdicts.db` — pre-populated with sample verdicts

---

## Migration

No migration needed. New tables are created via `CREATE TABLE IF NOT EXISTS` in `OpenCache()`. Existing DBs work unchanged.

---

## Implementation Order

1. Schema: add `verdicts` and `learned_weights` tables to `OpenCache()`
2. File pattern extraction: `ExtractFilePattern()` function
3. Bayesian smoothing: `ComputeWeightedFPStats()` with decay
4. Modifier computation: `ComputeModifier()` with smoothing, ramp-up, cap, clamp
5. Tier classification: `ClassifyTier()` from sample count
6. Verdict command: `cmd/verdict.go` with --stats
7. Scorer extension: `ScoreWithAdaptive()` method
8. Finding struct: add `AdaptiveModifier` + `LearningTier` fields
9. Scanner wiring: load weights, apply modifier in scan pipeline
10. CLI flags: `--adaptive` on scan, `--cache-db` on verdict
11. Output format updates: text, JSON, SARIF, markdown, CSV, HTML
12. Tests: unit + integration (smoothing, ramp-up, cap, tier, full flow)
13. Documentation: ARCHITECTURE.md update, README additions

---

## Future Work (V8+)

### Verdict Reasons

Extend the verdict command to accept a reason:

```bash
syck verdict abc123 fp --reason test_fixture --cache-db scan.db
syck verdict def456 fp --reason dummy_data --cache-db scan.db
```

Schema addition:
```sql
ALTER TABLE verdicts ADD COLUMN reason TEXT;
```

Value: discover patterns like "90% of FPs come from test fixtures" which can inform rule tuning automatically.

### Confidence Band Recalibration

Use verdict history to adjust band thresholds. If the system learns that 70% of "HIGH" findings are actually FP, the HIGH band threshold could shift upward.

### Rule Suggestion Engine

Analyze high-confidence TP patterns to suggest new rules. If a regex consistently catches real secrets with 100% TP rate, it could be promoted to a built-in rule.
