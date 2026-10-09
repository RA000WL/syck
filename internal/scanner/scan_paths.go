package scanner

import (
	"fmt"
	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/correlator"
	"github.com/RA000WL/syck/internal/finding"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// reportProgress fires the progress callback (if set) with the current file
// and findings counts. Safe to call concurrently.
func reportProgress(cfg Config, files *atomic.Int64, findings *atomic.Int64) {
	if cfg.Progress == nil {
		return
	}
	cfg.Progress(int(files.Load()), int(findings.Load()))
}

func ScanPaths(paths []string, cfg Config) ([]finding.Finding, error) {
	var (
		allFindings   []finding.Finding
		mu            sync.Mutex
		wg            sync.WaitGroup
		sem           = make(chan struct{}, EffectiveWorkers(cfg.Workers))
		filesScanned  atomic.Int64
		totalFindings atomic.Int64
	)

	// Open mtime cache once for the entire scan (if enabled)
	var mtimeCache *correlator.Cache
	if cfg.CacheDB != "" {
		if c, err := correlator.OpenCache(cfg.CacheDB); err == nil {
			mtimeCache = c
			defer mtimeCache.Close()
		}
	}

	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			if cfg.Debug {
				fmt.Fprintf(os.Stderr, "[debug] stat %s: %v\n", root, err)
			}
			continue
		}
		if !info.IsDir() {
			// Mtime skip: skip unchanged files
			if mtimeCache != nil && mtimeCache.ShouldSkipFile(root, info.ModTime().Unix()) {
				if cfg.Debug {
					fmt.Fprintf(os.Stderr, "[debug] skip (unchanged): %s\n", root)
				}
				continue
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(path, cfg)
				// Record mtime after scan
				if mtimeCache != nil {
					if fi, ferr := os.Stat(path); ferr == nil {
						if mErr := mtimeCache.RecordFileMtime(path, fi.ModTime().Unix()); mErr != nil && cfg.Debug {
							fmt.Fprintf(os.Stderr, "[debug] record mtime %s: %v\n", path, mErr)
						}
					}
				}
				filesScanned.Add(1)
				if err != nil {
					if cfg.Debug {
						fmt.Fprintf(os.Stderr, "[debug] scan %s: %v\n", path, err)
					}
				}
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					totalFindings.Add(int64(len(findings)))
					mu.Unlock()
				}
				reportProgress(cfg, &filesScanned, &totalFindings)
			}(root)
			continue
		}

		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				if skipDirs[info.Name()] {
					return filepath.SkipDir
				}
				if cfg.ExcludeDir != nil && cfg.ExcludeDir.MatchString(info.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if cfg.Exclude != nil && cfg.Exclude.MatchString(path) {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if !textExtensions[ext] && !isTextFile(path) {
				if cfg.ScanBinaries {
					isBinaryExt := ext == ".exe" || ext == ".dll" || ext == ".so" ||
						ext == ".dylib" || ext == ".class" || ext == ".pyc" ||
						ext == ".o" || ext == ".obj" || ext == ".wasm"
					if isBinaryExt {
						sem <- struct{}{}
						wg.Add(1)
						go func(fp string) {
							defer wg.Done()
							defer func() { <-sem }()
							filesScanned.Add(1)
							f, e := ScanBinaryFile(fp, cfg)
							if e == nil && len(f) > 0 {
								mu.Lock()
								allFindings = append(allFindings, f...)
								totalFindings.Add(int64(len(f)))
								mu.Unlock()
							}
						}(path)
						return nil
					}
				}
				return nil
			}
			if cfg.MaxFileSize > 0 && info.Size() > cfg.MaxFileSize {
				return nil
			}
			// Mtime skip: skip unchanged files
			if mtimeCache != nil && mtimeCache.ShouldSkipFile(path, info.ModTime().Unix()) {
				if cfg.Debug {
					fmt.Fprintf(os.Stderr, "[debug] skip (unchanged): %s\n", path)
				}
				return nil
			}

			sem <- struct{}{}
			wg.Add(1)
			go func(fp string) {
				defer wg.Done()
				defer func() { <-sem }()
				findings, err := ScanFile(fp, cfg)
				// Record mtime after scan
				if mtimeCache != nil {
					if fi, ferr := os.Stat(fp); ferr == nil {
						if mErr := mtimeCache.RecordFileMtime(fp, fi.ModTime().Unix()); mErr != nil && cfg.Debug {
							fmt.Fprintf(os.Stderr, "[debug] record mtime %s: %v\n", fp, mErr)
						}
					}
				}
				filesScanned.Add(1)
				if err != nil {
					if cfg.Debug {
						fmt.Fprintf(os.Stderr, "[debug] scan %s: %v\n", fp, err)
					}
				}
				if err == nil && len(findings) > 0 {
					mu.Lock()
					allFindings = append(allFindings, findings...)
					totalFindings.Add(int64(len(findings)))
					mu.Unlock()
				}
				reportProgress(cfg, &filesScanned, &totalFindings)
			}(path)
			return nil
		})
		if err != nil {
			continue
		}
	}

	wg.Wait()

	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
		allFindings = finding.DeduplicateBySecret(allFindings)
	}

	if cfg.DowngradeFP {
		allFindings = DowngradeFP(allFindings)
	}

	// Credential pairs run at the collection boundary, so a pair is described in
	// terms of the components as they are actually reported (post-dedup,
	// post-FP-downgrade) and is gated on MinSeverity itself — the rule paths
	// already did that while matching, and nothing after collection repeats it.
	allFindings = correlateFindings(cfg, allFindings)

	if cfg.CacheDB != "" {
		cache, err := correlator.OpenCache(cfg.CacheDB)
		if err == nil {
			recordFingerprints(cache, allFindings)
			if cfg.Adaptive && cfg.AdaptiveWeights != nil {
				for i := range allFindings {
					filePattern := adaptive.ExtractFilePattern(allFindings[i].File)
					w := cfg.AdaptiveWeights.Get(allFindings[i].RuleName, filePattern)
					if w != nil {
						allFindings[i].AdaptiveModifier = int(w.Modifier)
						allFindings[i].LearningTier = w.Tier.Label()
					}
				}
			}
			cache.Close()
		}
	}

	return allFindings, nil
}

// recordFingerprints records every finding in the cross-run cache and then
// back-fills IsNew onto all findings sharing a newly recorded fingerprint.
//
// RecordWithMeta only reports isNew for the INSERT that wins the UNIQUE
// constraint on fingerprint, and Fingerprint is RuleName|Secret|File — no line
// or column. With per-occurrence dedup one secret used on N lines produces N
// findings over one fingerprint, so trusting the return value alone would mark
// occurrence 1 new and occurrences 2..N as already-known on their very first
// sight, which is wrong for --diff. Fingerprint is deliberately left
// position-free so a secret that moves a line is still "known".
func recordFingerprints(cache *correlator.Cache, findings []finding.Finding) {
	newFingerprints := make(map[string]bool)
	for i := range findings {
		fp := correlator.Fingerprint(findings[i].RuleName, findings[i].Secret, findings[i].File)
		if isNew, _ := cache.RecordWithMeta(fp, findings[i].RuleName, findings[i].Secret, findings[i].File); isNew {
			newFingerprints[fp] = true
		}
	}
	if len(newFingerprints) == 0 {
		return
	}
	for i := range findings {
		fp := correlator.Fingerprint(findings[i].RuleName, findings[i].Secret, findings[i].File)
		if newFingerprints[fp] {
			findings[i].IsNew = true
		}
	}
}
