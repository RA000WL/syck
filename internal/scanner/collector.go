package scanner

import (
	"os"
	"path/filepath"
)

type FileJob struct {
	Path string
	Size int64
}

type Collector struct {
	cfg Config
}

func NewCollector(cfg Config) *Collector { return &Collector{cfg: cfg} }

var scannerSkipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	"vendor": true, "target": true, "build": true, "dist": true,
}

func (c *Collector) Walk(root string) (<-chan FileJob, error) {
	out := make(chan FileJob, 64)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if scannerSkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if c.cfg.MaxFileSize > 0 && info.Size() > c.cfg.MaxFileSize {
			return nil
		}
		if c.cfg.Exclude != nil && c.cfg.Exclude.MatchString(path) {
			return nil
		}
		out <- FileJob{Path: path, Size: info.Size()}
		return nil
	})
	close(out)
	return out, walkErr
}
