package scanner

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/RA000WL/syck/internal/finding"
)

const workersTestRules = "rules:\n  - name: test_token\n    severity: HIGH\n    pattern: 'TOKEN_[A-Z0-9]{8}'\n"

func TestEffectiveWorkers(t *testing.T) {
	if got := EffectiveWorkers(7); got != 7 {
		t.Errorf("EffectiveWorkers(7) = %d, want 7 (positive passthrough)", got)
	}
	if got := EffectiveWorkers(1); got != 1 {
		t.Errorf("EffectiveWorkers(1) = %d, want 1 (one worker is legal)", got)
	}
	if got := EffectiveWorkers(0); got < 2 {
		t.Errorf("EffectiveWorkers(0) = %d, want >= 2", got)
	}
	if got := EffectiveWorkers(-3); got < 2 {
		t.Errorf("EffectiveWorkers(-3) = %d, want >= 2", got)
	}
	if zero, neg := EffectiveWorkers(0), EffectiveWorkers(-3); zero != neg {
		t.Errorf("EffectiveWorkers(0) = %d and EffectiveWorkers(-3) = %d, want the same clamped default", zero, neg)
	}
}

// A zero or negative Workers value must never reach make(chan struct{}, n):
// a zero-capacity semaphore blocks forever on the first send, so the walk
// hangs instead of scanning. The timeout guard turns that hang into a
// failure rather than a stuck suite.
func TestScanPathsZeroWorkersDoesNotHang(t *testing.T) {
	type result struct {
		findings []finding.Finding
		err      error
	}

	dir := t.TempDir()
	for name, content := range map[string]string{
		"a.txt": "a = TOKEN_ABCDEF12\n",
		"b.txt": "b = TOKEN_ZYXW9876\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, workers := range []int{0, -3} {
		t.Run("workers="+strconv.Itoa(workers), func(t *testing.T) {
			cfg := Config{
				Rules:       loadTestRuleSet(t, workersTestRules),
				MinSeverity: finding.ParseSeverity("LOW"),
				Workers:     workers,
			}

			done := make(chan result, 1)
			go func() {
				f, err := ScanPaths([]string{dir}, cfg)
				done <- result{findings: f, err: err}
			}()

			select {
			case r := <-done:
				if r.err != nil {
					t.Fatalf("ScanPaths(Workers: %d): %v", workers, r.err)
				}
				if got := countSecret(r.findings, "TOKEN_ABCDEF12"); got < 1 {
					t.Errorf("ScanPaths(Workers: %d) reported %d occurrences of the fixture secret, want >= 1 (clamped run must still scan)",
						workers, got)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("ScanPaths(Workers: %d) did not return within 10s (zero-capacity semaphore deadlock)", workers)
			}
		})
	}
}
