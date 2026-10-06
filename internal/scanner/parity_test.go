package scanner

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/RA000WL/syck/internal/finding"
	"github.com/RA000WL/syck/internal/rules"
)

// Regeneration: go test ./internal/scanner/ -run TestParity -update
//
// A flag var is preferred over a build tag here: regeneration is a normal
// in-band operation a developer runs on demand, and a build tag would require
// every contributor to remember a non-default compilation mode. The flag keeps
// `go test` behavior identical for CI (the golden is only written when
// -update is passed explicitly) while staying one command away.
var updateParity = flag.Bool("update", false, "regenerate the parity golden file")

// TestParityFindingsUnchanged is the batch-4a keystone: a snapshot of every
// finding the default 199-rule set produces over the small mixed-language
// corpus in testdata/parity. Batches 4b (god-file splits), 4c (detection
// dedup) and 4d (debt sweep) must prove their refactors did not move this
// snapshot.
func TestParityFindingsUnchanged(t *testing.T) {
	rs, err := rules.LoadDefault()
	if err != nil {
		t.Fatalf("load default rules: %v", err)
	}
	cfg := Config{
		Rules:       rs,
		Workers:     1, // deterministic; ordering is pinned by the sort below anyway
		MinSeverity: finding.SeverityLow,
		NoDedup:     false,
		DowngradeFP: true,
		// Opt into the two decoder paths the corpus exercises so the golden
		// captures decoded findings too; flags off would silently drop them.
		DecodeBase64: true,
		DecodeJWT:    true,
	}

	const root = "testdata/parity"
	paths := parityFixturePaths(t, root)

	findings, err := ScanPaths(paths, cfg)
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}

	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			t.Fatalf("relativize %q: %v", f.File, err)
		}
		lines = append(lines, fmt.Sprintf("%s:%d\t%s\t%s", rel, f.Line, f.RuleName, finding.SeverityNames[f.Severity]))
	}
	sort.Strings(lines)
	got := ""
	if len(lines) > 0 {
		got = strings.Join(lines, "\n") + "\n"
	}

	golden := filepath.Join(root, "golden.txt")
	if *updateParity {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d findings)", golden, len(lines))
		return
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if got != string(want) {
		t.Fatalf("parity golden drift:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// parityFixturePaths returns every regular file under testdata/parity except
// golden.txt itself. Skipping the golden keeps the scan self-reference-free:
// golden.txt is scanner output, and re-scanning it on later runs would feed
// yesterday's findings back into today's snapshot.
func parityFixturePaths(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "golden.txt" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(paths)
	return paths
}
